# Securescope: a hardened Gradescope autograder

Securescope is an autograder base Docker image for Gradescope with improved security.

> The following documentation assumes familiarity with Gradescope's autograder flow and requirements. For more information, please refer to [Gradescope's autograder documentation](https://gradescope-autograders.readthedocs.io/en/latest/manual_docker/).

## Motivation

Gradescope's default autograder setup does not implement any kind of security restrictions and trusts arbitrary user code entirely.

Since 2016, there have been a number of examples of how student code can abuse this trust:

* In 2016, MIT students [discovered](https://courses.csail.mit.edu/6.857/2016/files/20.pdf#subsection.5.3) that Gradescope does not limit network connections or file system access for student code.
* In 2019, a UPenn student published a [proof-of-concept](https://www.seas.upenn.edu/~hanbangw/blog/hack-gs/) method for changing one's grade, modifying the `run_autograder` shell entrypoint to have arbitrary writes to `results.json` take final effect.
* In 2020, another [writeup](https://medium.com/@andylyu/how-a-frustrating-computer-science-assignment-lead-to-me-gaining-access-to-the-server-that-graded-502310cf03ae) was published that demonstrated how to gain unrestricted access to the Docker container hosting an autograder by running a reverse shell from submitted code. This also allowed exfiltrating hidden test cases.

Gradescope's response to the 2020 writeup acknowledged these issues, but suggested it would be difficult to remediate any of the insecurities in a way compatible with most custom autograder code. In my February 2023 testing of Gradescope's Ubuntu 22.04 base Docker image and an example [Python calculator](https://github.com/gradescope/autograder_samples/tree/master/python) autograder, I was able to replicate and exploit each of the above vulnerabilities.

The hardened Docker image provided here adds several security mechanisms that should not need much restructuring of client autograder code.

## Implemented security mechanisms

### Deprivileging student submissions

Securescope creates a deprivileged `student` user with UID `1001`. The intention is that any untrusted student submission should be run under the `student` user rather than `root` (the Gradescope default).

> Note that an unmodified autograder client will still run code as `root` here by default. This is because the entire `/autograder` directory (except for `/autograder/results`) is owned by `root`, but custom autograders often run setup tasks that write to `/autograder` before running student code. If the entire custom autograder chain was run as `student`, these setup tasks would be blocked.

To take advantage of the `student` user, it is suggested that you modify the `/autograder/run_autograder` entrypoint to:

* Centralize all setup tasks that write to `/autograder`
* Give the `student` user appropriate permissions for any files it may need to write to
* Execute the remainder of an autograder chain as the `student` user, e.g. `su student -c "run_tests"`

> See an example: [Python calculator's `run_autograder`](examples/python-calculator/run_autograder)

### Blocking network requests

Securescope can block any attempts to create network connections, preventing reverse shells and test case exfiltration.

> Note that because Gradescope does not run Docker containers with the right privileges to implement a proper `iptables` firewall, Securescope uses `seccomp` to prevent the autograder chain from making `socket` system calls of type `AF_INET` (IPv4) or `AF_INET6` (IPv6). This means that even connections to the loopback address (`localhost`/`127.0.0.1`) are blocked, which may interfere with some grader code e.g. Jupyter Notebook.
>
> **As such, this functionality is disabled by default.**

To take advantage of network request blocking, it is suggested that you run any tasks that may need internet connectivity in the Dockerfile deriving from Securescope.

To enable network request blocking, set the `SECCOMP_BLOCK_IP` environment variable to `true`, i.e. by adding the following line to your `Dockerfile`:

```docker
ENV SECCOMP_BLOCK_IP true
```

### Verifying result integrity

Securescope can detect tampering with the `results.json` file before upload to Gradescope's submission API.

To do this, Securescope's modified harness generates a cryptographic nonce that is provided to client autograder code via an environment variable. The presence of the nonce in `results.json` is verified by the harness before uploading the results to Gradescope's API.

Autograder client code is required to:

1. Read the `AUTOGRADER_NONCE` environment variable and store it in memory, out of scope from student code.
2. Clear the `AUTOGRADER_NONCE` environment variable.
3. Before exiting, add the nonce to `results.json` as a string value associated with the top-level `nonce` key.

**This functionality is disabled by default.**

To enable nonce verification, set the `VERIFY_NONCE` environment variable to `true`, i.e. by adding the following line to your `Dockerfile`:

```docker
ENV VERIFY_NONCE true
```

> Note that it would still be possible for student code to modify `results.json` *even after the nonce is added* by using `inotify` events to watch for changes to `results.json`. To prevent this attack, Securescope can use `seccomp` to block the `inotify_add_watch` system call; enable this by setting the `SECCOMP_BLOCK_INOTIFY` environment variable to `true`.
>
> **This is also disabled by default** to prevent interference with client autograder code that may depend on `inotify`.

## Usage

Usage of Securescope should work the same way as [extending a base Gradescope autograder docker image](https://gradescope-autograders.readthedocs.io/en/latest/manual_docker/). For example, see the following Dockerfile.

```Docker
ARG BASE_REPO=saligrama/securescope
ARG TAG=ubuntu-2204

FROM ${BASE_REPO}:${TAG}

ADD source /autograder/source

RUN cp /autograder/source/run_autograder /autograder/run_autograder

# Ensure that scripts are Unix-friendly and executable
RUN dos2unix /autograder/run_autograder /autograder/source/setup.sh
RUN chmod +x /autograder/run_autograder

RUN /autograder/source/setup.sh

# Example: install extras needed by your autograder
RUN pip install numpy

# Example: enable network request blocking
ENV SECCOMP_BLOCK_IP true

# Example: enable nonce verification to detect submission tampering
ENV VERIFY_NONCE true

# Example: enable inotify watch blocking
ENV SECCOMP_BLOCK_INOTIFY true
```