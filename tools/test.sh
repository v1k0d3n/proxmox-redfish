#!/bin/bash
# Test runner for proxmox-redfish
export PYTHONPATH=src
pytest "$@" 