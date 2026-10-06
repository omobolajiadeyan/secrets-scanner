import unittest
from pathlib import Path


class ActionInputSafetyTests(unittest.TestCase):
    def test_inputs_are_passed_through_environment_not_run_script_interpolation(self):
        action = (Path(__file__).resolve().parent.parent / "action.yml").read_text()
        run_script = action.split("      run: |", 1)[1]

        self.assertIn("SCAN_PATH: ${{ inputs.path }}", action)
        self.assertIn("SCAN_SEVERITY: ${{ inputs.severity }}", action)
        self.assertIn("SCAN_OUTPUT: ${{ inputs.output }}", action)
        self.assertNotIn("${{", run_script)
        self.assertIn('"$SCAN_PATH"', run_script)
        self.assertIn('"$SCAN_SEVERITY"', run_script)
        self.assertIn('"$SCAN_OUTPUT"', run_script)


if __name__ == "__main__":
    unittest.main()
