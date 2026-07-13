from app.services.tool_output_compression import compress_tool_output


def test_empty_and_blank_input() -> None:
    assert compress_tool_output("") == ""
    assert compress_tool_output("   \n\n  ") == ""


def test_small_output_passes_through_untouched() -> None:
    text = "real0.tarcisio.blog. 377 IN A 203.0.113.0\nreal1.tarcisio.blog. 377 IN A 203.0.113.1"
    assert compress_tool_output(text) == text


def test_collapses_a_generic_wildcard_style_flood() -> None:
    # Same shape as the dnsenum incident, but any tool could produce this:
    # many distinct hostnames, same trailing shape, all resolving to one IP.
    flood = "\n".join(
        f"guess{i}.tarcisio.blog.                 377      IN    A        72.60.2.144"
        for i in range(200)
    )
    compressed = compress_tool_output(flood, max_chars=100_000)
    lines = compressed.splitlines()
    assert len(lines) == 2  # first sample + one summary note
    assert "guess0.tarcisio.blog." in lines[0]
    assert "+199 linhas parecidas" in lines[1]


def test_does_not_collapse_below_min_group_size() -> None:
    text = "\n".join(f"real{i}.example.com found" for i in range(3))
    assert compress_tool_output(text, min_group_size=4) == text


def test_truncates_with_placeholder_when_over_budget() -> None:
    text = "x" * 5000
    compressed = compress_tool_output(text, max_chars=100)
    assert compressed.startswith("x" * 100)
    assert "caracteres cortados" in compressed
    assert "saida completa em disco" in compressed


def test_preserves_order_around_a_flood() -> None:
    lines = ["start marker"]
    lines += [f"noise{i}.example.com A 1.2.3.4" for i in range(10)]
    lines.append("end marker")
    compressed = compress_tool_output("\n".join(lines), max_chars=100_000)
    out_lines = compressed.splitlines()
    assert out_lines[0] == "start marker"
    assert out_lines[-1] == "end marker"
