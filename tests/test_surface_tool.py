"""Tests for tools/surface.py."""

from memory.pattern_db import PatternDB
from memory.schemas import make_pattern_entry
from memory.target_profile import make_target_profile, save_target_profile
from surface import format_surface_output, load_surface_context, rank_surface


class TestSurfaceContext:

    def test_loads_real_recon_layout_and_memory(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "\n".join([
                "https://api.target.com [200] [API] [Next.js,GraphQL,nginx] [1234]",
                "https://docs.target.com [403] [Documentation] [cloudflare] [456]",
            ]) + "\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/v2/users?id=123\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("/ws/notifications\n")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["next.js", "graphql"],
            tested_endpoints=["/api/v2/users/123"],
            untested_endpoints=["/graphql", "/api/v2/users?id=123"],
            hunt_sessions=2,
        ))
        PatternDB(memory_dir / "patterns.jsonl").save(make_pattern_entry(
            target="alpha.com",
            vuln_class="idor",
            technique="numeric_id_swap",
            tech_stack=["graphql"],
            payout=800,
        ))

        context = load_surface_context(repo_root, "target.com", memory_dir=memory_dir)
        assert context["available"] is True
        assert "https://api.target.com/graphql" in context["api_urls"]
        assert "/ws/notifications" in context["js_endpoints"]
        assert context["profile"]["hunt_sessions"] == 2


class TestSurfaceRanking:

    def test_ranks_graphql_and_untested_high(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "\n".join([
                "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]",
                "https://docs.target.com [403] [Documentation] [cloudflare] [500]",
            ]) + "\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/v2/report?id=123\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=["/api/v2/users/123"],
            untested_endpoints=["/graphql", "/api/v2/report?id=123"],
            hunt_sessions=1,
        ))
        PatternDB(memory_dir / "patterns.jsonl").save(make_pattern_entry(
            target="beta.com",
            vuln_class="idor",
            technique="id_swap",
            tech_stack=["graphql"],
            payout=500,
        ))

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=memory_dir))
        assert ranked["available"] is True
        assert ranked["p1"]
        assert "graphql" in ranked["p1"][0]["url"]
        kill_hosts = [item["host"] for item in [__import__("json").loads(x) for x in ranked["kill"]]]
        assert "docs.target.com" in kill_hosts

    def test_format_missing_recon(self):
        output = format_surface_output({"available": False}, "missing.com")
        assert "No recon data found for missing.com." in output
