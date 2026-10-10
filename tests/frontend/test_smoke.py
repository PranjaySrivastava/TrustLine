"""
Frontend Dashboard Smoke Tests
Owner: Yajas (with Pranjay oversight)
"""
import os

def test_dashboard_files_exist():
    assert os.path.exists("dashboard/index.html")
