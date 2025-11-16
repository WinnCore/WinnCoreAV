#!/usr/bin/env python3
"""
WinnCoreAV - Advanced Feature Extraction for ML Detection
Extracts 40+ features from ARM64 ELF binaries for malware classification
"""

import os
import sys
import struct
import math
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import Counter
import csv

class ARM64FeatureExtractor:
    """Extract comprehensive features from ARM64 ELF binaries"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = 0
        self.data = b''
        self.features = {}

        # Load file
        try:
            with open(file_path, 'rb') as f:
                self.data = f.read()
            self.file_size = len(self.data)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            self.data = b''

    def extract_all_features(self) -> Dict[str, float]:
        """Extract all 40+ features"""
        if not self.data:
            return self._empty_features()

        features = {}

        # Basic file features
        features.update(self._extract_basic_features())

        # ELF header features
        features.update(self._extract_elf_features())

        # Section features
        features.update(self._extract_section_features())

        # Entropy features
        features.update(self._extract_entropy_features())

        # String analysis features
        features.update(self._extract_string_features())

        # ARM64 instruction features
        features.update(self._extract_instruction_features())

        # Import/export features
        features.update(self._extract_symbol_features())

        # Behavioral indicators
        features.update(self._extract_behavioral_features())

        # Advanced static analysis
        features.update(self._extract_advanced_features())

        return features

    def _extract_basic_features(self) -> Dict[str, float]:
        """Extract basic file features"""
        return {
            'file_size': float(self.file_size),
            'file_size_log': math.log(max(self.file_size, 1)),
        }

    def _extract_elf_features(self) -> Dict[str, float]:
        """Extract ELF header features"""
        features = {
            'is_elf': 0.0,
            'is_arm64': 0.0,
            'is_executable': 0.0,
            'num_program_headers': 0.0,
            'num_section_headers': 0.0,
            'entry_point': 0.0,
        }

        if len(self.data) < 64:
            return features

        # Check ELF magic
        if self.data[:4] == b'\x7fELF':
            features['is_elf'] = 1.0

            # Check if ARM64
            e_machine = struct.unpack('<H', self.data[18:20])[0]
            if e_machine == 183:  # EM_AARCH64
                features['is_arm64'] = 1.0

            # Check if executable
            e_type = struct.unpack('<H', self.data[16:18])[0]
            if e_type == 2:  # ET_EXEC
                features['is_executable'] = 1.0

            # Get header counts
            features['num_program_headers'] = float(struct.unpack('<H', self.data[56:58])[0])
            features['num_section_headers'] = float(struct.unpack('<H', self.data[60:62])[0])

            # Entry point
            entry_point = struct.unpack('<Q', self.data[24:32])[0]
            features['entry_point'] = math.log(max(entry_point, 1))

        return features

    def _extract_section_features(self) -> Dict[str, float]:
        """Extract section-related features"""
        features = {
            'num_executable_sections': 0.0,
            'num_writable_sections': 0.0,
            'num_wx_sections': 0.0,  # Writable + Executable (suspicious)
            'code_to_data_ratio': 0.0,
            'unusual_section_names': 0.0,
        }

        if len(self.data) < 64 or self.data[:4] != b'\x7fELF':
            return features

        # Parse section headers
        try:
            e_shoff = struct.unpack('<Q', self.data[40:48])[0]
            e_shnum = struct.unpack('<H', self.data[60:62])[0]
            e_shentsize = struct.unpack('<H', self.data[58:60])[0]

            code_size = 0
            data_size = 0
            unusual_names = ['hidden', 'inject', 'hook', 'evil', 'malw']

            for i in range(e_shnum):
                offset = e_shoff + (i * e_shentsize)
                if offset + 64 > len(self.data):
                    break

                sh_type = struct.unpack('<I', self.data[offset+4:offset+8])[0]
                sh_flags = struct.unpack('<Q', self.data[offset+8:offset+16])[0]
                sh_size = struct.unpack('<Q', self.data[offset+32:offset+40])[0]

                # Check flags
                is_exec = (sh_flags & 0x4) != 0
                is_write = (sh_flags & 0x1) != 0
                is_alloc = (sh_flags & 0x2) != 0

                if is_exec:
                    features['num_executable_sections'] += 1.0
                    code_size += sh_size

                if is_write:
                    features['num_writable_sections'] += 1.0
                    data_size += sh_size

                if is_exec and is_write:
                    features['num_wx_sections'] += 1.0

            # Code to data ratio
            if data_size > 0:
                features['code_to_data_ratio'] = float(code_size) / float(data_size)

        except Exception:
            pass

        return features

    def _extract_entropy_features(self) -> Dict[str, float]:
        """Extract entropy-based features"""
        features = {
            'overall_entropy': 0.0,
            'section_entropy_variance': 0.0,
            'max_entropy': 0.0,
            'min_entropy': 8.0,
            'high_entropy_sections': 0.0,
        }

        # Calculate overall entropy
        features['overall_entropy'] = self._calculate_entropy(self.data)

        # Calculate entropy for different sections of the file
        chunk_size = max(len(self.data) // 10, 1024)
        entropies = []

        for i in range(0, len(self.data), chunk_size):
            chunk = self.data[i:i+chunk_size]
            if len(chunk) > 0:
                ent = self._calculate_entropy(chunk)
                entropies.append(ent)

                if ent > 7.0:  # High entropy (possibly encrypted/packed)
                    features['high_entropy_sections'] += 1.0

        if entropies:
            features['max_entropy'] = max(entropies)
            features['min_entropy'] = min(entropies)

            # Variance in entropy (packed files have high variance)
            mean_ent = sum(entropies) / len(entropies)
            variance = sum((e - mean_ent) ** 2 for e in entropies) / len(entropies)
            features['section_entropy_variance'] = variance

        return features

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0

        entropy = 0.0
        counter = Counter(data)
        length = len(data)

        for count in counter.values():
            p = float(count) / length
            entropy -= p * math.log2(p)

        return entropy

    def _extract_string_features(self) -> Dict[str, float]:
        """Extract string-based features"""
        features = {
            'url_count': 0.0,
            'ip_count': 0.0,
            'email_count': 0.0,
            'crypto_wallet_patterns': 0.0,
            'shell_command_patterns': 0.0,
            'suspicious_string_count': 0.0,
            'printable_string_ratio': 0.0,
        }

        # Extract printable strings
        strings = self._extract_strings(self.data)

        # Count printable characters
        printable = sum(1 for b in self.data if 32 <= b <= 126)
        features['printable_string_ratio'] = float(printable) / max(len(self.data), 1)

        # Pattern matching
        url_pattern = re.compile(rb'https?://[^\s]+')
        ip_pattern = re.compile(rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        email_pattern = re.compile(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

        # Crypto wallet patterns (Bitcoin, Monero, etc.)
        crypto_patterns = [
            rb'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',  # Bitcoin
            rb'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}',  # Monero
            rb'0x[a-fA-F0-9]{40}',                  # Ethereum
        ]

        # Shell command patterns
        shell_patterns = [
            rb'wget\s+',
            rb'curl\s+',
            rb'chmod\s+\+x',
            rb'rm\s+-rf',
            rb'/bin/sh',
            rb'/bin/bash',
            rb'sh\s+-c',
            rb'eval\(',
        ]

        # Suspicious strings
        suspicious_patterns = [
            rb'pool\.',
            rb'stratum',
            rb'cryptonight',
            rb'xmrig',
            rb'miner',
            rb'backdoor',
            rb'rootkit',
            rb'keylog',
            rb'LD_PRELOAD',
            rb'/dev/null',
            rb'\[kworker',
        ]

        features['url_count'] = len(url_pattern.findall(self.data))
        features['ip_count'] = len(ip_pattern.findall(self.data))
        features['email_count'] = len(email_pattern.findall(self.data))

        for pattern in crypto_patterns:
            features['crypto_wallet_patterns'] += len(re.findall(pattern, self.data))

        for pattern in shell_patterns:
            features['shell_command_patterns'] += len(re.findall(pattern, self.data))

        for pattern in suspicious_patterns:
            features['suspicious_string_count'] += len(re.findall(pattern, self.data))

        return features

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[bytes]:
        """Extract printable strings from binary"""
        strings = []
        current = bytearray()

        for byte in data:
            if 32 <= byte <= 126:
                current.append(byte)
            else:
                if len(current) >= min_len:
                    strings.append(bytes(current))
                current = bytearray()

        if len(current) >= min_len:
            strings.append(bytes(current))

        return strings

    def _extract_instruction_features(self) -> Dict[str, float]:
        """Extract ARM64 instruction patterns"""
        features = {
            'syscall_count': 0.0,
            'branch_count': 0.0,
            'crypto_instruction_count': 0.0,
            'suspicious_syscalls': 0.0,
        }

        # Scan for ARM64 instruction patterns
        for i in range(0, len(self.data) - 4, 4):
            try:
                instr = struct.unpack('<I', self.data[i:i+4])[0]

                # SVC instruction (syscall)
                if (instr & 0xFFE0001F) == 0xD4000001:
                    features['syscall_count'] += 1.0

                # Branch instructions
                if (instr & 0xFC000000) == 0x14000000:  # B
                    features['branch_count'] += 1.0
                elif (instr & 0xFC000000) == 0x94000000:  # BL
                    features['branch_count'] += 1.0

                # Crypto instructions (AES, SHA)
                if (instr & 0xFFE0FC00) == 0x4E284800:  # AESE
                    features['crypto_instruction_count'] += 1.0
                elif (instr & 0xFFE0FC00) == 0x4E285800:  # AESD
                    features['crypto_instruction_count'] += 1.0

            except Exception:
                continue

        return features

    def _extract_symbol_features(self) -> Dict[str, float]:
        """Extract import/export features"""
        features = {
            'import_count': 0.0,
            'export_count': 0.0,
            'import_export_ratio': 0.0,
            'suspicious_imports': 0.0,
        }

        # Simple heuristic: count potential symbol table entries
        # In a real implementation, you'd parse the symbol table properly
        symbol_patterns = [
            rb'socket',
            rb'connect',
            rb'fork',
            rb'execve',
            rb'ptrace',
            rb'prctl',
        ]

        for pattern in symbol_patterns:
            if pattern in self.data:
                features['import_count'] += 1.0
                features['suspicious_imports'] += 1.0

        if features['import_count'] > 0 and features['export_count'] > 0:
            features['import_export_ratio'] = features['import_count'] / features['export_count']

        return features

    def _extract_behavioral_features(self) -> Dict[str, float]:
        """Extract behavioral indicators"""
        features = {
            'network_indicators': 0.0,
            'file_operation_indicators': 0.0,
            'process_indicators': 0.0,
            'persistence_indicators': 0.0,
            'anti_debug_indicators': 0.0,
        }

        # Network indicators
        network_patterns = [rb'connect', rb'socket', rb'bind', rb'listen', rb'send', rb'recv']
        for pattern in network_patterns:
            if pattern in self.data:
                features['network_indicators'] += 1.0

        # File operation indicators
        file_patterns = [rb'open', rb'read', rb'write', rb'unlink', rb'chmod']
        for pattern in file_patterns:
            if pattern in self.data:
                features['file_operation_indicators'] += 1.0

        # Process indicators
        process_patterns = [rb'fork', rb'execve', rb'clone', rb'waitpid']
        for pattern in process_patterns:
            if pattern in self.data:
                features['process_indicators'] += 1.0

        # Persistence indicators
        persistence_patterns = [rb'cron', rb'systemd', rb'rc.local', rb'bashrc']
        for pattern in persistence_patterns:
            if pattern in self.data:
                features['persistence_indicators'] += 1.0

        # Anti-debugging indicators
        debug_patterns = [rb'ptrace', rb'TracerPid', rb'/proc/self/status']
        for pattern in debug_patterns:
            if pattern in self.data:
                features['anti_debug_indicators'] += 1.0

        return features

    def _extract_advanced_features(self) -> Dict[str, float]:
        """Extract advanced static analysis features"""
        features = {
            'overlay_data_present': 0.0,
            'timestamp_anomaly': 0.0,
            'debug_info_present': 0.0,
            'stripped': 0.0,
            'packed_indicator': 0.0,
        }

        # Check for debug info
        if b'.debug' in self.data or b'DWARF' in self.data:
            features['debug_info_present'] = 1.0
        else:
            features['stripped'] = 1.0

        # Packed indicator (high entropy + small imports)
        if features.get('overall_entropy', 0) > 7.5:
            features['packed_indicator'] = 1.0

        # Overlay data (data after last section)
        # This would require proper ELF parsing - simplified here
        if len(self.data) > 100000:  # Large file might have overlay
            features['overlay_data_present'] = 0.5

        return features

    def _empty_features(self) -> Dict[str, float]:
        """Return empty feature dict when file can't be processed"""
        feature_names = [
            'file_size', 'file_size_log', 'is_elf', 'is_arm64', 'is_executable',
            'num_program_headers', 'num_section_headers', 'entry_point',
            'num_executable_sections', 'num_writable_sections', 'num_wx_sections',
            'code_to_data_ratio', 'unusual_section_names', 'overall_entropy',
            'section_entropy_variance', 'max_entropy', 'min_entropy', 'high_entropy_sections',
            'url_count', 'ip_count', 'email_count', 'crypto_wallet_patterns',
            'shell_command_patterns', 'suspicious_string_count', 'printable_string_ratio',
            'syscall_count', 'branch_count', 'crypto_instruction_count', 'suspicious_syscalls',
            'import_count', 'export_count', 'import_export_ratio', 'suspicious_imports',
            'network_indicators', 'file_operation_indicators', 'process_indicators',
            'persistence_indicators', 'anti_debug_indicators', 'overlay_data_present',
            'timestamp_anomaly', 'debug_info_present', 'stripped', 'packed_indicator',
        ]
        return {name: 0.0 for name in feature_names}


def extract_dataset_features(sample_dirs: List[Tuple[str, int]], output_csv: str):
    """Extract features from entire dataset"""
    print("Extracting features from dataset...")

    all_features = []
    feature_names = None

    total_samples = sum(len(list(Path(d).glob('*'))) for d, _ in sample_dirs if Path(d).exists())
    processed = 0

    for sample_dir, label in sample_dirs:
        sample_path = Path(sample_dir)
        if not sample_path.exists():
            print(f"Warning: {sample_dir} does not exist, skipping...")
            continue

        label_name = "malware" if label == 1 else "benign"
        print(f"\nProcessing {label_name} samples from {sample_dir}...")

        for sample_file in sample_path.glob('*'):
            if sample_file.is_file():
                try:
                    extractor = ARM64FeatureExtractor(str(sample_file))
                    features = extractor.extract_all_features()
                    features['label'] = label
                    features['file_path'] = str(sample_file)

                    if feature_names is None:
                        feature_names = sorted([k for k in features.keys() if k not in ['label', 'file_path']])

                    all_features.append(features)
                    processed += 1

                    if processed % 100 == 0:
                        print(f"  Processed {processed}/{total_samples} samples...")

                except Exception as e:
                    print(f"  Error processing {sample_file}: {e}")

    # Write to CSV
    print(f"\nWriting features to {output_csv}...")

    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['file_path'] + feature_names + ['label']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for features in all_features:
            writer.writerow(features)

    print(f"\n✅ Extracted {len(all_features)} samples with {len(feature_names)} features")
    print(f"   Malware: {sum(1 for f in all_features if f['label'] == 1)}")
    print(f"   Benign: {sum(1 for f in all_features if f['label'] == 0)}")

    return len(all_features), len(feature_names)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Extract features from ARM64 binaries')
    parser.add_argument('--output', '-o', default='features.csv',
                       help='Output CSV file')
    parser.add_argument('--benign-dir', '-b', default='/usr/bin',
                       help='Directory containing benign samples')
    parser.add_argument('--malware-dirs', '-m', nargs='+',
                       default=['samples/malware/level1', 'samples/malware/level2', 'samples/malware/level3'],
                       help='Directories containing malware samples')

    args = parser.parse_args()

    # Build sample directory list
    sample_dirs = []

    # Add benign samples
    sample_dirs.append((args.benign_dir, 0))

    # Add malware samples
    for malware_dir in args.malware_dirs:
        sample_dirs.append((malware_dir, 1))

    # Extract features
    extract_dataset_features(sample_dirs, args.output)


if __name__ == '__main__':
    main()
