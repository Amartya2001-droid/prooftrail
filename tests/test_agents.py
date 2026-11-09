"""Agent registry: five named roles, each with a stable id, a display
name, a one-line role description and a list of capabilities."""

import unittest

from prooftrail.agents import get_role, list_roles


class TestAgentRegistry(unittest.TestCase):
    def test_five_roles_registered(self):
        self.assertEqual(len(list_roles()), 5)

    def test_role_ids_are_stable_and_unique(self):
        ids = [role.agent_id for role in list_roles()]
        self.assertEqual(ids, ["orchestrator", "verifier", "detective",
                               "cartographer", "narrator"])
        self.assertEqual(len(set(ids)), len(ids))

    def test_lookup_by_id(self):
        role = get_role("verifier")
        self.assertEqual(role.name, "Verity")
        self.assertIn("hash chains", role.role)
        self.assertIn("verify signatures", role.capabilities)

    def test_each_role_has_name_description_and_capabilities(self):
        for role in list_roles():
            self.assertTrue(role.name)
            self.assertTrue(role.role)
            self.assertTrue(role.capabilities)

    def test_display_names(self):
        names = {role.agent_id: role.name for role in list_roles()}
        self.assertEqual(names, {
            "orchestrator": "Trailboss",
            "verifier": "Verity",
            "detective": "Sleuth",
            "cartographer": "Mapper",
            "narrator": "Scribe",
        })

    def test_unknown_id_raises(self):
        with self.assertRaises(KeyError):
            get_role("no-such-agent")

    def test_list_returns_a_copy(self):
        roles = list_roles()
        roles.clear()
        self.assertEqual(len(list_roles()), 5)


if __name__ == "__main__":
    unittest.main()
