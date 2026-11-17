#!/bin/bash
# DRY-RUN ONLY (agent 385). Stands in for `docker` inside a dry-run container that has no daemon.
# Answers exactly `docker image inspect <the pinned sp1-gnark digest>` (the prover installer's presence check)
# and refuses every other call, so no step that would really run a container can pass by accident.
PIN=ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d
if [ "$#" = 3 ] && [ "$1" = image ] && [ "$2" = inspect ] && [ "$3" = "$PIN" ]; then
  echo '[{"RepoDigests":["'"$PIN"'"],"Comment":"dry-run shim: the real host must hold this image"}]'
  exit 0
fi
if [ "$#" = 1 ] && [ "$1" = ps ]; then
  echo 'CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES'
  exit 0
fi
echo "docker dry-run shim: refused: docker $*" >&2
exit 64
