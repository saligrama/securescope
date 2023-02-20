import json
import os
import unittest
from gradescope_utils.autograder_utils.json_test_runner import JSONTestRunner

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover("tests")

    nonce = os.getenv("AUTOGRADER_NONCE")
    os.environ.pop("AUTOGRADER_NONCE", None)

    with open("/autograder/results/results.json", "w") as f:
        JSONTestRunner(visibility="visible", stream=f).run(suite)

    result = json.load(open("/autograder/results/results.json", "r"))
    result["nonce"] = nonce
    json.dump(result, open("/autograder/results/results.json", "w"), indent=2)
