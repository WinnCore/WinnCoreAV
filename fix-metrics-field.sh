#!/bin/bash

echo "Adding metrics field to FileMonitor struct..."

# Find the struct and add metrics field
# We'll use a careful find-and-replace

# First, let's see the exact struct
echo "Current struct:"
sed -n '/pub struct FileMonitor {/,/^}/p' av-daemon/src/monitor.rs

# Add metrics field after stats field
sed -i '/stats: Arc<ScanStats>,/a\    metrics: Arc<Metrics>,' av-daemon/src/monitor.rs

echo -e "\nUpdated struct:"
sed -n '/pub struct FileMonitor {/,/^}/p' av-daemon/src/monitor.rs

# Now we need to ensure it's stored in the constructor
echo -e "\nChecking constructor..."
grep -A 30 "pub fn new(" av-daemon/src/monitor.rs | grep -A 20 "Ok(Self"

