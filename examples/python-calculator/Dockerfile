ARG BASE_REPO=saligrama/securescope
ARG TAG=ubuntu-2204

FROM ${BASE_REPO}:${TAG}

ADD source /autograder/source

RUN cp /autograder/source/run_autograder /autograder/run_autograder

# Ensure that scripts are Unix-friendly and executable
RUN dos2unix /autograder/run_autograder /autograder/source/setup.sh
RUN chmod +x /autograder/run_autograder

RUN /autograder/source/setup.sh

# Example: enable network request blocking
ENV SECCOMP_BLOCK_IP true

# Example: enable nonce verification to detect submission tampering
ENV VERIFY_NONCE true

# Example: enable inotify watch blocking
ENV SECCOMP_BLOCK_INOTIFY true