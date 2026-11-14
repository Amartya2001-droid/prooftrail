"""Synthetic announcement fixture shared by the CLI and guided browser demo.

Demo actors are freshly generated signing keys, not user accounts or evidence of
real authorship. Their private keys are discarded after fixture creation.
"""
from .store import Actor, Project

V1 = ("Acadia Robotics Club announces its spring showcase. "
      "The showcase opens on 14 March at the Student Union Building. "
      "Admission is free for all students.")
V2 = (V1 + " Our robots will demonstrate line following, maze solving, "
      "and sumo wrestling. Bring your friends and meet the team "
      "behind the machines.")
V3 = ("Acadia Robotics Club invites everyone to its spring showcase. "
      "Join us on 14 March at the Student Union Building for an "
      "evening of live robot demos. Watch our robots follow lines, "
      "solve mazes, and battle in sumo wrestling. "
      "Admission is free, and everyone is welcome.")


TITLE = "Demo — Robotics Showcase Announcement"


def sample_project(owner: Actor, project_id: str, clock) -> Project:
    project = Project(project_id, TITLE)
    project.add_collaborator(owner)
    project.creator_id = owner.actor_id
    writer = Actor.create(project_id + "-writer", "Demo writer (synthetic)")
    editor = Actor.create(project_id + "-editor", "Demo editor (synthetic)")
    project.add_collaborator(writer)
    project.add_collaborator(editor)
    for actor, text, label in ((writer, V1, "v1"), (editor, V2, "v2")):
        project.upload(actor, text.encode(), clock(), label,
                       filename=label + ".txt", content_type="text/plain")
    project.declare(editor, project.versions[1], "ChatGPT",
                    "Synthetic demo declaration: draft the demo paragraph", [], clock())
    project.upload(editor, V3.encode(), clock(), "v3",
                   filename="v3.txt", content_type="text/plain")
    writer.secret_key = b""
    editor.secret_key = b""
    return project
