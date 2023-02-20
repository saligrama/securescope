#! /usr/bin/env python3
# Version: 0.15.0

import grequests
import requests
import os
import time
import os.path
import shutil
import errno
import json
import subprocess
import sys
import traceback
import codecs
import secrets
from threading import Timer


class HTTPFailure(Exception):
    pass


def safe_request(method, url, attempts=5, timeout=30, **kwargs):
    attempt = 0
    while attempt < attempts:
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
            return response
        except:
            attempt += 1
            time.sleep(1)
    raise HTTPFailure()


def safe_get(url, attempts=5, timeout=30, **kwargs):
    return safe_request("get", url, attempts, timeout, **kwargs)


def safe_post(url, attempts=5, timeout=60, **kwargs):
    return safe_request("post", url, attempts, timeout, **kwargs)


def safe_patch(url, attempts=5, timeout=60, **kwargs):
    return safe_request("patch", url, attempts, timeout, **kwargs)


def safe_delete(url, attempts=5, timeout=60, **kwargs):
    return safe_request("delete", url, attempts, timeout, **kwargs)


def grequests_exception_handler(request, exception):
    print("Exception in grequests:")
    print(exception)
    raise HTTPFailure()


def safe_parallel_get(urls, attempts=2, timeout=30):
    attempt = 0
    while attempt < attempts:
        try:
            requests = (grequests.get(url, timeout=timeout) for url in urls)
            responses = grequests.map(
                requests, size=10, exception_handler=grequests_exception_handler
            )
            return responses
        except:
            attempt += 1
            time.sleep(1)
    raise HTTPFailure()


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def kill_proc(proc, timed_out):
    timed_out["value"] = True
    proc.kill()


def timeout_process(proc, timeout_seconds):
    timed_out = {"value": False}
    timer = Timer(timeout_seconds, kill_proc, [proc, timed_out])

    try:
        timer.start()
        start_time = time.time()
        proc.wait()
        end_time = time.time()
    finally:
        timer.cancel()

    elapsed_time = end_time - start_time

    return proc.returncode, elapsed_time, timed_out["value"]


def pretty_time_delta(seconds):
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days > 0:
        return "%dd%dh%dm%ds" % (days, hours, minutes, seconds)
    elif hours > 0:
        return "%dh%dm%ds" % (hours, minutes, seconds)
    elif minutes > 0:
        return "%dm%ds" % (minutes, seconds)
    else:
        return "%ds" % (seconds,)


def warn_user_for_timeout(remaining_seconds):
    warning_msg = (
        f"[Warning] Your SSH session will end in {pretty_time_delta(remaining_seconds)}"
    )
    print(f"Sending warning message: {warning_msg}")
    os.system(f"echo {warning_msg} | wall -n")


def clean_string(string):
    """Replaces null characters which are found in some autograder output"""
    return string.replace("\x00", "\uFFFD")


MAX_OUTPUT_LENGTH = 100000
TRUNCATION_MESSAGE = "[...(truncated)...]"


def truncate_output(output):
    """Truncate output so that it is shorter than MAX_OUTPUT_LENGTH"""
    if output is not None and len(output) > MAX_OUTPUT_LENGTH:
        half_of_max_output_length = (MAX_OUTPUT_LENGTH - len(TRUNCATION_MESSAGE)) // 2
        output_start = output[:half_of_max_output_length]
        output_end = output[len(output) - half_of_max_output_length :]
        return f"{output_start}{TRUNCATION_MESSAGE}{output_end}"
    return output


def truncate_results(results):
    if results is None:
        return
    if "output" in results:
        results["output"] = truncate_output(results["output"])
    if results.get("tests"):
        for test in results["tests"]:
            if "output" in test:
                test["output"] = truncate_output(test["output"])


class AutograderHarness(object):
    def __init__(self):
        self._devel = os.getenv("DEVEL")
        self.elapsed_time = 0
        self.raw_results = ""
        self.submission_path = "/autograder/submission"
        self.results_path = "/autograder/results"

    def prepare_submission(self):
        shutil.rmtree(self.submission_path, ignore_errors=True)
        os.mkdir(self.submission_path)

        shutil.rmtree(self.results_path, ignore_errors=True)
        os.mkdir(self.results_path)

        # Make the student user own results, so the child process can write to it
        os.chown(self.results_path, 1001, 1001)

    def load_payload(self):
        if self._devel:
            self._load_devel_payload()
        else:
            self._load_payload()
        os.environ.pop("START_SSHD", None)
        os.environ.pop("AUTHENTICATION_TOKEN", None)

    def _load_devel_payload(self):
        self._load_payload()
        self.submit_results_url = self.submission_url[0:-5] + "/submit_results"

    def _load_payload(self):
        self.authentication_token = os.getenv("AUTHENTICATION_TOKEN")
        self.submission_url = os.getenv("SUBMISSION_URL")
        self.submit_results_url = os.getenv("SUBMIT_RESULTS_URL")
        self.asset_host = os.getenv("ASSET_HOST")
        self.timeout_seconds = int(os.getenv("TIMEOUT_SECONDS", default=20 * 60))
        self.start_sshd = os.getenv("START_SSHD") == "true"
        self.sshd_timeout_warning_seconds = int(
            os.getenv("SSHD_TIMEOUT_WARNING_SECONDS", default=5 * 60)
        )
        self.authorized_keys = os.getenv("AUTHORIZED_KEYS")
        self.verify_nonce = os.getenv("VERIFY_NONCE") == "true"

        basic_auth = os.getenv("BASIC_AUTH")
        if basic_auth is not None:
            self.basic_auth = tuple(basic_auth.split(":"))
        else:
            self.basic_auth = None

    def report_status(self, status):
        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth

        kwargs["headers"] = {"access-token": self.authentication_token}
        payload = {"programming_assignment_submission": {"status": status}}
        kwargs["json"] = payload
        safe_patch(self.submission_url, **kwargs)

    def report_ssh_status(self, status):
        ssh_session_url = self.submission_url[0:-5] + "/ssh_session"
        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth

        kwargs["headers"] = {"access-token": self.authentication_token}
        payload = {}
        kwargs["json"] = payload
        if status == "started":
            safe_patch(ssh_session_url, **kwargs)
        elif status == "stopped":
            safe_delete(ssh_session_url, **kwargs)

    def report_failure(self, error_code, error_message, output_message, stdout=""):
        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth

        kwargs["headers"] = {"access-token": self.authentication_token}
        results = {
            "score": 0,
            "output": output_message,
        }

        payload = {
            "programming_assignment": {
                "stdout": stdout,
                "results": results,
                "error_code": error_code,
                "error_message": error_message,
                "elapsed_time": self.elapsed_time,
            }
        }

        kwargs["json"] = payload

        safe_post(self.submit_results_url, **kwargs)
        sys.exit(1)

    def report_http_failure(self, error_message):
        output_message = "The autograder failed to execute correctly. Please try submitting it again. Contact us at help@gradescope.com if the autograder continues to fail."
        self.report_failure("http", error_message, output_message)

    def report_autograder_failure(self, error_message, stdout):
        output_message = "The autograder failed to execute correctly. Please ensure that your submission is valid. Contact your course staff for help in debugging this issue. Make sure to include a link to this page so that they can help you most effectively."
        self.report_failure("autograder", error_message, output_message, stdout)

    def fetch_submission(self):
        print("Fetching submission")

        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth
        kwargs["headers"] = {"access-token": self.authentication_token}

        response = safe_get(self.submission_url, **kwargs)

        self.submission_json = response.json()
        self.write_metadata()
        self.fetch_files()

    def prepare_file_metadata(self):
        self.files = []
        for file in self.submission_json["files"]:
            url = file["url"]
            if url[0] == "/" and self.asset_host:
                url = self.asset_host + url

            path = file["path"]
            local_path = os.path.join(self.submission_path, path)

            file["url"] = url
            file["path"] = local_path

            self.files.append(file)

    def fetch_files(self):
        self.prepare_file_metadata()

        print("Fetching files...")
        urls = [f["url"] for f in self.files]
        responses = safe_parallel_get(urls)

        for file, response in zip(self.files, responses):
            path = file["path"]
            mkdir_p(os.path.dirname(path))
            with open(path, "wb") as f:
                f.write(response.content)

        print("Files downloaded.")

    def write_metadata(self):
        with open("/autograder/submission_metadata.json", "w") as f:
            metadata = {
                "id": self.submission_json["id"],
                "users": self.submission_json["active_users"],
                "created_at": self.submission_json["created_at"],
                "assignment_id": self.submission_json.get("assignment_id"),
                "assignment": self.submission_json.get("assignment"),
                "submission_method": self.submission_json.get("submission_method"),
                "previous_submissions": self.submission_json["previous_submissions"],
            }
            json.dump(metadata, f)

    def run_autograder(self):
        print("Running autograder.")
        if self.verify_nonce:
            os.environ["AUTOGRADER_NONCE"] = self.nonce
        p = subprocess.Popen(
            "./second_stage.py",
            cwd="/autograder",
        )
        exit_status, elapsed_time, timed_out = timeout_process(p, self.timeout_seconds)
        self.elapsed_time = elapsed_time
        self.exit_status = exit_status

        if timed_out:
            result = {
                "score": 0,
                "output": "Your submission timed out. It took longer than {0} seconds to run.".format(
                    self.timeout_seconds
                ),
                "execution_time": self.elapsed_time,
            }
            results_path = os.path.join(self.results_path, "results.json")
            with open(results_path, "w") as f:
                json.dump(result, f)

    def read_stdout(self):
        stdout = ""
        stdout_path = os.path.join(self.results_path, "stdout")
        if os.path.exists(stdout_path):
            with codecs.open(stdout_path, "r", encoding="utf-8", errors="replace") as f:
                stdout = f.read()
        return clean_string(stdout)

    def read_results(self):
        results_path = os.path.join(self.results_path, "results.json")

        if not os.path.exists(results_path):
            return None

        with codecs.open(results_path, "r", encoding="utf-8", errors="replace") as f:
            self.raw_results = f.read()
            try:
                results = json.loads(clean_string(self.raw_results))
            except ValueError:
                return self.raw_results

        return results

    def submit_results(self):
        stdout = truncate_output(self.read_stdout())
        results = self.read_results()
        error_code = None

        if isinstance(results, str):
            stdout += "\nYour results.json file could not be parsed as JSON. Its contents are as follows:\n\n"
            stdout += results

            results = {
                "score": 0,
                "output": "The autograder failed to execute correctly. Please ensure that your submission is valid. Contact your course staff for help in debugging this issue. Make sure to include a link to this page so that they can help you most effectively.",
            }
            error_code = "invalid_json"

        if (
            self.verify_nonce
            and results != None
            and ("nonce" not in results.keys() or results["nonce"] != self.nonce)
        ):
            stdout += "\nThe student submission was rejected as cryptographic nonce verification failed. This may suggest that the student is trying to tamper with the autograder's results."
            stdout += f"\nResults (JSON):\n {json.dumps(results, indent=2)}"
            stdout += f"\nExpected nonce: {self.nonce}"

            results = {
                "score": 0,
                "output": "Please contact an instructor for guidance on processing your score.",
            }
            error_code = "noncefail"

        truncate_results(results)

        payload = {
            "programming_assignment": {
                "stdout": stdout,
                "results": results,
                "elapsed_time": self.elapsed_time,
                "exit_status": self.exit_status,
                "error_code": error_code,
                "raw_results": truncate_output(self.raw_results),
            }
        }

        kwargs = {}
        if self.basic_auth is not None:
            kwargs["auth"] = self.basic_auth
        kwargs["headers"] = {"access-token": self.authentication_token}
        kwargs["json"] = payload

        safe_post(self.submit_results_url, **kwargs)

    def add_authorized_keys(self):
        with open("/root/.ssh/authorized_keys", "w") as f:
            f.write(self.authorized_keys)

    def run_sshd(self):
        child = subprocess.Popen("/usr/local/sbin/start_sshd.sh")
        self.report_ssh_status("started")
        warning_time_seconds = self.sshd_timeout_warning_seconds
        warning_timer = Timer(
            self.timeout_seconds - warning_time_seconds,
            warn_user_for_timeout,
            [warning_time_seconds],
        )
        warning_timer.start()
        timeout_process(child, self.timeout_seconds)
        warning_timer.cancel()
        self.report_ssh_status("stopped")

    def run(self):
        self.load_payload()
        self.prepare_submission()

        if not self.submission_url:
            raise Exception("SUBMISSION_URL or PAYLOAD_FILE required")

        self.report_status("harness_started")
        try:
            self.fetch_submission()
        except:
            self.report_http_failure(
                "The autograder failed while fetching the submission from Gradescope."
            )

        if self.start_sshd:
            self.add_authorized_keys()
            self.run_sshd()
            return

        if self.verify_nonce:
            self.nonce = secrets.token_urlsafe()

        try:
            self.run_autograder()
        except Exception as e:
            self.report_autograder_failure(
                "The autograder failed to run.", traceback.format_exc()
            )

        try:
            self.submit_results()
        except:
            self.report_http_failure(
                "The autograder failed while submitting results to Gradescope."
            )


if __name__ == "__main__":
    harness = AutograderHarness()
    harness.run()
