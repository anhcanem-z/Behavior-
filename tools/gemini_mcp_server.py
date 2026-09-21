#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple MCP server that forwards Claude requests to Gemini AGY.

It reads a JSON request from stdin, extracts a prompt, invokes `agy`
with the Gemini 3.8 Flash (High) model, and writes a JSON response
to stdout.
"""
import json, sys, subprocess, os, shlex

def read_request():
    try:
        data = sys.stdin.read()
        if not data:
            return {}
        return json.loads(data)
    except Exception as e:
        return {"error": f"Failed to read request: {e}"}

def extract_prompt(req):
    # Claude may send a list of messages; use the last user message if present
    if "prompt" in req:
        return req["prompt"]
    if "messages" in req:
        # Find last message from user role if available
        for msg in reversed(req["messages"]):
            if msg.get("role") == "user":
                # content may be list of parts
                content = msg.get("content", [])
                if isinstance(content, list) and content:
                    part = content[0]
                    if isinstance(part, dict):
                        return part.get("text", "")
                return ""
    return ""

def call_agy(prompt):
    # Build the agy command
    agy_cmd = ["agy", "-p", prompt, "--model", "Gemini 3.8 Flash (High)"]
    try:
        result = subprocess.run(agy_cmd, capture_output=True, text=True, env=os.environ)
        if result.returncode != 0:
            return {"error": f"agy exited {result.returncode}: {result.stderr.strip()}"}
        return {"content": result.stdout.strip()}
    except Exception as e:
        return {"error": f"Exception calling agy: {e}"}

def main():
    req = read_request()
    if req.get("error"):
        print(json.dumps({"error": req["error"]}))
        sys.exit(1)
    prompt = extract_prompt(req)
    if not prompt:
        print(json.dumps({"error": "No prompt found in request"}))
        sys.exit(1)
    resp = call_agy(prompt)
    print(json.dumps(resp))

if __name__ == "__main__":
    main()
