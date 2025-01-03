import hashlib
import argparse
import logging
import pandas as pd
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def calculate_hash(file_path, hash_algorithm='sha256'):
    """Calculates the cryptographic hash of a file.

    Args:
        file_path (str): The path to the file.
        hash_algorithm (str): The hashing algorithm to use (e.g., 'sha256', 'md5'). Defaults to 'sha256'.

    Returns:
        str: The hexadecimal representation of the calculated hash, or None on error.
    """
    try:
        # Validate file path
        if not os.path.isfile(file_path):
            logging.error(f"File not found: {file_path}")
            return None

        # Validate hash algorithm
        if hash_algorithm not in hashlib.algorithms_available:
            logging.error(f"Invalid hash algorithm: {hash_algorithm}")
            return None

        hasher = hashlib.new(hash_algorithm)
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(4096)  # Read file in chunks to handle large files efficiently
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None


def compare_hashes(file_path1, file_path2, hash_algorithm='sha256'):
    """Compares the hashes of two files.

    Args:
        file_path1 (str): The path to the first file.
        file_path2 (str): The path to the second file.
        hash_algorithm (str): The hashing algorithm to use. Defaults to 'sha256'.

    Returns:
        bool: True if the hashes are identical, False otherwise, or None on error.
    """
    hash1 = calculate_hash(file_path1, hash_algorithm)
    hash2 = calculate_hash(file_path2, hash_algorithm)

    if hash1 is None or hash2 is None:
        return None

    return hash1 == hash2


def analyze_directory(directory_path, hash_algorithm='sha256'):
    """Calculates and stores hashes for all files in the given directory into a Pandas DataFrame.

     Args:
        directory_path (str): The path to the directory.
        hash_algorithm (str): The hashing algorithm to use. Defaults to 'sha256'.
    
     Returns:
        pd.DataFrame: A DataFrame containing file paths and their corresponding hashes, or None on error.
    """
    try:
        # Validate directory path
        if not os.path.isdir(directory_path):
            logging.error(f"Directory not found: {directory_path}")
            return None
        
        file_data = []
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            if os.path.isfile(file_path):
                file_hash = calculate_hash(file_path, hash_algorithm)
                if file_hash is not None:
                    file_data.append({'file_path': file_path, 'hash': file_hash})
        return pd.DataFrame(file_data)
    except Exception as e:
        logging.error(f"Error analyzing directory {directory_path}: {e}")
        return None



def setup_argparse():
    """Sets up the command line argument parser."""
    parser = argparse.ArgumentParser(description="Calculate and compare file hashes.")
    parser.add_argument('command', choices=['hash', 'compare', 'analyze'],
                         help="Command to execute: hash, compare, or analyze")
    parser.add_argument('-f1', '--file1', help="Path to the first file")
    parser.add_argument('-f2', '--file2', help="Path to the second file, required for 'compare'")
    parser.add_argument('-d', '--directory', help="Path to the directory, required for 'analyze'")
    parser.add_argument('-a', '--algorithm', default='sha256', help="Hashing algorithm (e.g., sha256, md5). Defaults to sha256.")
    return parser


def main():
    """Main entry point for the script."""
    parser = setup_argparse()
    args = parser.parse_args()

    if args.command == 'hash':
        if not args.file1:
           parser.error("The 'hash' command requires --file1")
        file_hash = calculate_hash(args.file1, args.algorithm)
        if file_hash:
            print(f"Hash of {args.file1}: {file_hash}")
        else:
            logging.error("Could not calculate hash.")

    elif args.command == 'compare':
        if not args.file1 or not args.file2:
           parser.error("The 'compare' command requires both --file1 and --file2")
        are_equal = compare_hashes(args.file1, args.file2, args.algorithm)
        if are_equal is None:
            logging.error("Could not compare hashes.")
        elif are_equal:
            print("Hashes are identical.")
        else:
            print("Hashes are different.")
    
    elif args.command == 'analyze':
        if not args.directory:
            parser.error("The 'analyze' command requires --directory")
        df = analyze_directory(args.directory, args.algorithm)
        if df is not None:
            print(df.to_string())
        else:
            logging.error("Could not analyze the directory.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()