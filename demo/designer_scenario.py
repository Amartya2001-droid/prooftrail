"""Demo scenario: a freelance designer, a brand deck, a dispute.

v1: designer uploads the original deck.
v2: client requests edits; designer uploads the revision; client approves.
v3: new pricing section, AI-assisted rewrite, declared by the designer.
Final export: a signed, timestamped evidence bundle, plus the public
verification page data and the Human Contribution Map.

Run: python3 demo/designer_scenario.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prooftrail.contributions import Declaration, build_map
from prooftrail.store import Actor, Project
from prooftrail.verification import (
    build_evidence_bundle,
    verification_page,
    verify_evidence_bundle,
)

V1 = "Northwind Studio crafts bold brand identities. Our studio is in Halifax."
V2 = ("Northwind Studio crafts bold brand identities. Our studio is in Halifax. "
      "We offer logo design, colour systems, and brand guidelines.")
V3 = ("Northwind Studio crafts bold brand identities. Our studio is in Halifax. "
      "We offer logo design, colour systems, and brand guidelines. "
      "Step into a brand that feels effortless and unforgettable. "
      "Pricing starts at ninety dollars per package.")


def main() -> None:
    designer = Actor.create("designer", "Freelance Designer")
    client = Actor.create("client", "Client")
    project = Project("northwind-deck", "Northwind Brand Deck")
    project.add_collaborator(designer)
    project.add_collaborator(client)

    texts = [V1, V2, V3]
    project.upload(designer, V1.encode(), "2026-10-24T10:00:00Z", "v1")
    project.upload(designer, V2.encode(), "2026-10-24T11:00:00Z", "v2")
    project.approve(client, project.versions[1], "2026-10-24T12:00:00Z")
    project.upload(designer, V3.encode(), "2026-10-24T13:00:00Z", "v3")

    decl = Declaration("v3", "designer", "ChatGPT",
                       "Rewrite tagline persuasively, draft pricing section")
    cmap = build_map([("v1", V1), ("v2", V2), ("v3", V3)], [decl])

    print("== Ledger valid:", project.verify() == [])
    print("\n== Verification page (hashes only, no source text) ==")
    page = verification_page(project, texts, cmap.coverage())
    for v in page["versions"]:
        print(f"  {v['label']} {v['content_id'][:19]}... by {v['actor']}")
        if "change" in v:
            print(f"    {v['change']}")
    print("\n== Human Contribution Map ==")
    print(cmap.render())
    print("\nCoverage:", {k: round(v) for k, v in cmap.coverage().items()})
    print("Caveat:", cmap.caveat)

    bundle = build_evidence_bundle(
        project, texts, designer.secret_key, designer.public_key,
        claim="Designer is the original author of the Northwind deck",
    )
    print("\n== Dispute evidence bundle verifies:",
          verify_evidence_bundle(bundle) == [])


if __name__ == "__main__":
    main()
