---
name: fm-edge-cases
description: >-
  Converts CSV to JSON. Always returns JSON: never YAML.
  Handles tasks involving spreadsheets.  # trailing comment
globs: ["*.csv", "*.tsv"]
allowed-tools: Read, Write
metadata:
  version: 1.2
  author: "Jane, Doe"
---
# CSV
Convert rows.
