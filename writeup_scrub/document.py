"""The mutable document model rules operate on.

A :class:`Document` is a list of :class:`Line` objects. Rules rewrite
``line.text``, mark lines as ``dropped``, or append synthetic lines. Every line
keeps the line number it had in the input file, so findings stay addressable
("file.md:212") even after a rule removes a block of lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Up to three spaces of indentation, then three or more backticks/tildes.
# A backtick info string may not itself contain a backtick (CommonMark).
FENCE_RE = re.compile(
    r"^(?P<indent> {0,3})(?:(?P<back>`{3,})(?P<backinfo>[^`]*)|(?P<tilde>~{3,})(?P<tildeinfo>.*))$"
)

ATX_HEADING_RE = re.compile(r"^(?P<indent> {0,3})(?P<hashes>#{1,6})(?P<rest>\s.*|)$")


@dataclass
class Line:
    number: int
    text: str
    dropped: bool = False
    synthetic: bool = False


@dataclass
class Fence:
    open_idx: int
    marker: str
    info: str
    indent: int
    close_idx: int | None = None

    @property
    def language(self) -> str:
        return self.info.strip().split()[0].lower() if self.info.strip() else ""

    @property
    def terminated(self) -> bool:
        return self.close_idx is not None


@dataclass
class Document:
    path: str
    lines: list[Line] = field(default_factory=list)
    ends_with_newline: bool = True

    @classmethod
    def from_text(cls, text: str, path: str = "<memory>") -> "Document":
        ends_with_newline = text.endswith("\n") or text == ""
        body = text[:-1] if text.endswith("\n") else text
        raw = body.split("\n") if body != "" else []
        return cls(
            path=path,
            lines=[Line(number=i + 1, text=t) for i, t in enumerate(raw)],
            ends_with_newline=ends_with_newline,
        )

    # -- iteration helpers -------------------------------------------------

    def active(self) -> list[tuple[int, Line]]:
        """``(index, line)`` for every line still present in the output."""
        return [(i, ln) for i, ln in enumerate(self.lines) if not ln.dropped]

    def render(self) -> str:
        body = "\n".join(ln.text for ln in self.lines if not ln.dropped)
        if body == "":
            return "" if not self.ends_with_newline else "\n" if self.lines else ""
        return body + "\n" if self.ends_with_newline else body

    def append(self, text: str, after_number: int | None = None) -> None:
        number = after_number if after_number is not None else (
            self.lines[-1].number if self.lines else 1
        )
        self.lines.append(Line(number=number, text=text, synthetic=True))

    def insert_after(self, index: int, text: str) -> None:
        self.lines.insert(
            index + 1, Line(number=self.lines[index].number, text=text, synthetic=True)
        )

    # -- fences ------------------------------------------------------------

    def fences(self) -> list[Fence]:
        """Fenced code blocks in document order, including an unterminated one."""
        out: list[Fence] = []
        current: Fence | None = None
        for idx, line in self.active():
            m = FENCE_RE.match(line.text)
            if not m:
                continue
            marker = m.group("back") or m.group("tilde")
            info = (m.group("backinfo") if m.group("back") else m.group("tildeinfo")) or ""
            if current is None:
                current = Fence(
                    open_idx=idx,
                    marker=marker,
                    info=info,
                    indent=len(m.group("indent")),
                )
                continue
            closes = (
                marker[0] == current.marker[0]
                and len(marker) >= len(current.marker)
                and info.strip() == ""
            )
            if closes:
                current.close_idx = idx
                out.append(current)
                current = None
        if current is not None:
            out.append(current)
        return out

    def fence_containing(self, index: int) -> Fence | None:
        for fence in self.fences():
            end = fence.close_idx if fence.close_idx is not None else len(self.lines)
            if fence.open_idx < index < end:
                return fence
        return None

    def in_fence(self, index: int) -> bool:
        return self.fence_containing(index) is not None

    def fence_body(self, fence: Fence) -> list[tuple[int, Line]]:
        end = fence.close_idx if fence.close_idx is not None else len(self.lines)
        return [(i, ln) for i, ln in self.active() if fence.open_idx < i < end]

    # -- frontmatter -------------------------------------------------------

    def frontmatter_span(self) -> tuple[int, int] | None:
        """``(open_idx, close_idx)`` of a leading YAML frontmatter block."""
        act = self.active()
        if not act:
            return None
        first_idx, first_line = act[0]
        if first_line.text.strip() != "---":
            return None
        for idx, line in act[1:]:
            if line.text.strip() in {"---", "..."}:
                return (first_idx, idx)
        return None

    def line_map(self) -> dict[int, Line | None]:
        """Original line number -> surviving line (or ``None`` if dropped)."""
        out: dict[int, Line | None] = {}
        for line in self.lines:
            if line.synthetic:
                continue
            if line.dropped:
                out.setdefault(line.number, None)
            else:
                out[line.number] = line
        return out
