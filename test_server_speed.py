#!/usr/bin/env python
"""Test server startup speed"""
import time
import sys

print("Testing server startup speed...")
start = time.time()

print("1. Importing Flask...")
t1 = time.time()
from flask import Flask
print(f"   Flask imported in {time.time() - t1:.3f}s")

print("2. Creating app...")
t2 = time.time()
app = Flask(__name__)
print(f"   App created in {time.time() - t2:.3f}s")

print("3. Adding route...")
t3 = time.time()
@app.route("/")
def index():
    return "OK"
print(f"   Route added in {time.time() - t3:.3f}s")

print(f"\nTotal startup time: {time.time() - start:.3f}s")
print("\nServer should start quickly now. If it's still slow, the issue is elsewhere.")

