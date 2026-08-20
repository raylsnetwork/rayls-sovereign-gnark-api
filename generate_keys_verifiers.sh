#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

BASE_DIR="."  # Adjust if needed

go run cmd/setup/setup_keys_verifiers/setup_keys_verifiers.go

# Function to convert new verifier format to old format
convert_verifier() {
    local input_file="$1"
    local output_file="$2"
    local temp_file=$(mktemp)
    
    if [ ! -f "$input_file" ]; then
        echo "Error: Input file $input_file not found"
        return 1
    fi
    
    echo "Converting $input_file to $output_file..."
    
    # Extract contract name from output filename
    local output_basename=$(basename "$output_file" .sol)
    local contract_name=""
    
    # Remove "_converted" suffix if present to get the intended contract name
    if [[ "$output_basename" == *"_converted" ]]; then
        contract_name=$(echo "$output_basename" | sed 's/_converted$//')
    else
        contract_name="$output_basename"
    fi
        
    echo "Using contract name: $contract_name"
    
    # First, create a temp file with comments before verifyProof removed
    local temp_no_comments=$(mktemp)
    
    # Remove documentation comments that appear right before verifyProof function
    awk '
    BEGIN { skip_comments = 0 }
    
    # If we hit /// comments, start looking ahead
    /^[[:space:]]*\/\/\// {
        if (!skip_comments) {
            # Store current position and start buffering
            skip_comments = 1
            comment_buffer = $0 "\n"
            next
        } else {
            # Continue buffering comments
            comment_buffer = comment_buffer $0 "\n"
            next
        }
    }
    
    # Empty lines while potentially skipping comments
    skip_comments && /^[[:space:]]*$/ {
        comment_buffer = comment_buffer $0 "\n"
        next
    }
    
    # Non-comment line after we were buffering comments
    skip_comments && !/^[[:space:]]*\/\/\// && !/^[[:space:]]*$/ {
        if (/function verifyProof\(/) {
            # This was indeed comments before verifyProof - skip them
            skip_comments = 0
            comment_buffer = ""
            print $0
        } else {
            # These were comments for something else - print them
            printf "%s", comment_buffer
            skip_comments = 0
            comment_buffer = ""
            print $0
        }
        next
    }
    
    # Any other line when not skipping comments
    !skip_comments { print }
    ' "$input_file" > "$temp_no_comments"
    
    # Process the file to convert the verifyProof function
    awk -v contract_name="$contract_name" '
    BEGIN { 
        in_verify_function = 0
        in_verify_signature = 0
        brace_count = 0
        printed_new_function = 0
        found_verify_function = 0
        signature_lines = ""
        input_array_size = 32  # default fallback
    }
    
    # Change contract name from Verifier to the derived contract name
    /^contract Verifier/ {
        gsub(/contract Verifier/, "contract " contract_name)
        print
        next
    }
    
    # Detect start of verifyProof function signature
    /function verifyProof\(/ {
        in_verify_signature = 1
        signature_lines = $0
        next
    }
    
    # Collect signature lines until we find the opening brace
    in_verify_signature && !in_verify_function {
        signature_lines = signature_lines " " $0
        if (/\{/) {
            # Check if this looks like the new signature pattern
            if (signature_lines ~ /uint256\[8\]/ || 
                (signature_lines ~ /proof/ && signature_lines ~ /input/)) {
                
                found_verify_function = 1
                
                # Extract input array size from the signature
                if (match(signature_lines, /uint256\[[0-9]+\][^0-9]*input/)) {
                    tmp = substr(signature_lines, RSTART, RLENGTH)
                    match(tmp, /\[[0-9]+\]/)
                    input_array_size = substr(tmp, RSTART+1, RLENGTH-2)
                    print "// Detected input array size: " input_array_size > "/dev/stderr"
                }
                
                if (!printed_new_function) {
                    print "    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[" input_array_size "] calldata _pubSignals) public view returns (bool) {"
                    print "        uint256[8] memory proof = ["
                    print "            _pA[0], _pA[1],"
                    print "            _pB[0][0], _pB[0][1],"  
                    print "            _pB[1][0], _pB[1][1],"
                    print "            _pC[0], _pC[1]"
                    print "        ];"
                    print "        "
                    print "        try this.verifyProofInternal(proof, _pubSignals) {"
                    print "            return true;"
                    print "        } catch {"
                    print "            return false;"
                    print "        }"
                    print "    }"
                    print ""
                    printed_new_function = 1
                }
                
                # Convert the original function
                gsub(/function verifyProof/, "function verifyProofInternal", signature_lines)
                gsub(/public view/, "external view", signature_lines)
                gsub(/returns \(bool\)/, "", signature_lines)
                gsub(/view returns \(bool\)/, "view", signature_lines)
                
                print signature_lines
                in_verify_function = 1
                in_verify_signature = 0
                brace_count = 1  # We found the opening brace
                next
            } else {
                # Not the signature we are looking for, print as-is
                print signature_lines
                in_verify_signature = 0
                signature_lines = ""
                next
            }
        }
        next
    }
    
    # Count braces while inside verifyProof function
    in_verify_function {
        for (i = 1; i <= length($0); i++) {
            char = substr($0, i, 1)
            if (char == "{") brace_count++
            if (char == "}") brace_count--
        }
        print
        
        if (brace_count == 0) {
            in_verify_function = 0
        }
        next
    }
    
    # Print all other lines
    { print }
    
    END {
        if (!found_verify_function) {
            print "Warning: No verifyProof function with new signature found in the input file" > "/dev/stderr"
        }
    }
    ' "$temp_no_comments" > "$temp_file"
    
    # Clean up temp file
    rm "$temp_no_comments"
    
    mv "$temp_file" "$output_file"
    echo "Conversion completed: $output_file (contract name: $contract_name)"
    
    # Enhanced file renaming logic for all verifier types
    local input_basename=$(basename "$input_file" .sol)
    local output_basename=$(basename "$output_file" .sol)
    local input_dir=$(dirname "$input_file")
    
    # Check if this is a converted file that needs renaming
    if [[ "$output_basename" == *"_converted" ]]; then
        echo "Renaming files for final output..."
        
        # Determine the target filename by removing "Enygma" prefix and "_converted" suffix
        local target_name=""
        

        # Generic pattern: remove "_converted" suffix
        target_name=$(echo "$output_basename" | sed 's/_converted$//')
   
        
        if [[ -n "$target_name" ]]; then
            local original_file="$input_dir/${target_name}.sol"
            local raw_file="$input_dir/${target_name}_raw.sol"
            local final_file="$input_dir/${target_name}.sol"
            
            # Check if original file exists
            if [[ -f "$original_file" ]]; then
                # Rename original to _raw
                mv "$original_file" "$raw_file"
                echo "  Original file renamed to: $raw_file"
            else
                echo "  Warning: Original file not found: $original_file"
            fi
            
            # Rename converted to original name
            mv "$output_file" "$final_file"
            echo "  Converted file renamed to: $final_file"
            
            echo "Final result:"
            echo "  - Original (backup): $raw_file"
            echo "  - Converted (active): $final_file"
            
            # Move the final converted file to appropriate target directory
            local target_dir=""
            local final_basename=$(basename "$final_file" .sol)
            
            # Determine target directory based on filename
            if [[ "$final_basename" == "EnygmaJoinSplitVerifier" ]] || \
               [[ "$final_basename" == "Erc721OwnershipVerifier" ]] || \
               [[ "$final_basename" == "Erc1155JoinSplitVerifier" ]]; then
                target_dir="$HOME/$BASE_DIR/rayls-sovereign-contracts/src/rayls-protocol/Enygma/Enygma-DVP"
                echo "File matches DVP pattern, routing to Enygma-DVP directory"
            else
                target_dir="$HOME/$BASE_DIR/rayls-sovereign-contracts/src/rayls-protocol/Enygma/Enygma-Payments"
                echo "File will go to Enygma-Payments directory"
            fi
            
            echo "Moving converted file to target directory..."
            # Create target directory if it doesn't exist
            if [ ! -d "$target_dir" ]; then
                echo "  Creating directory: $target_dir"
                mkdir -p "$target_dir"
            fi
            
            # Copy the converted file to target directory
            local target_file="$target_dir/$(basename "$final_file")"
            cp "$final_file" "$target_file"
            echo "  ✓ Copied to: $target_file"
        else
            echo "  Warning: Could not determine target filename for: $output_basename"
        fi
    else
        # If no renaming occurred, still move the output file if it's a conversion
        if [[ "$output_file" != "$input_file" ]]; then
            local target_dir=""
            local file_basename=$(basename "$output_file" .sol)
            
            # Determine target directory based on filename
            if [[ "$file_basename" == "EnygmaJoinSplitVerifier" ]] || \
               [[ "$file_basename" == "Erc721OwnershipVerifier" ]] || \
               [[ "$file_basename" == "Erc1155JoinSplitVerifier" ]]; then
                target_dir="$HOME/$BASE_DIR/rayls-sovereign-contracts/src/rayls-protocol/Enygma/Enygma-DVP"
                echo "File matches DVP pattern, routing to Enygma-DVP directory"
            else
                target_dir="$HOME/$BASE_DIR/rayls-sovereign-contracts/src/rayls-protocol/Enygma/Enygma-Payments"
                echo "File will go to Enygma-Payments directory"
            fi
            
            # Create target directory if it doesn't exist
            if [ ! -d "$target_dir" ]; then
                echo "  Creating directory: $target_dir"
                mkdir -p "$target_dir"
            fi
            
            # Copy the converted file to target directory
            local target_file="$target_dir/$(basename "$output_file")"
            cp "$output_file" "$target_file"
            echo "  ✓ Copied to: $target_file"
        fi
    fi
}

# Function to auto-detect and convert verifier files
find_and_convert_verifiers() {
    local found_files=()
    
    # Common paths where verifier contracts might be located
    local search_paths=(
        "./last_build"
    )
    
    echo "Searching for Verifier contracts that need conversion..."
    
    for path in "${search_paths[@]}"; do
        if [ -d "$path" ]; then
            echo "Checking directory: $path"
            # Look for Solidity files containing "contract Verifier" - avoid duplicates
            local files_in_dir=()
            while IFS= read -r file; do
                files_in_dir+=("$file")
            done < <(find "$path" -maxdepth 1 -name "*.sol" -type f 2>/dev/null | sort -u)
            
            for file in "${files_in_dir[@]}"; do
                if [ -f "$file" ] && grep -l "contract Verifier" "$file" >/dev/null 2>&1; then
                    echo "Found Verifier contract: $file"
                    
                    # Check if it has the new function signature (handle multi-line signatures)
                    local has_new_sig=false
                    if grep -A5 "function verifyProof" "$file" | grep -q "uint256\[8\]" ||
                       (grep -A5 "function verifyProof" "$file" | grep -q "proof" && 
                        grep -A5 "function verifyProof" "$file" | grep -q "input"); then
                        has_new_sig=true
                    fi
                    
                    local has_old_sig=false
                    if grep -A5 "function verifyProof" "$file" | grep -q "_pA.*_pB.*_pC"; then
                        has_old_sig=true
                    fi
                    
                    if [ "$has_new_sig" = true ] && [ "$has_old_sig" = false ]; then
                        echo "  -> Has new signature, will convert"
                        found_files+=("$file")
                        processed_files+=("$abs_file")
                    else
                        echo "  -> Already has old signature or unknown format (has_new_sig=$has_new_sig, has_old_sig=$has_old_sig)"
                        echo "  -> Function signature found:"
                        grep -A5 "function verifyProof" "$file" || echo "  -> No verifyProof function found"
                    fi
                fi
            done
        else
            echo "Directory $path does not exist"
        fi
    done
    
    if [ ${#found_files[@]} -eq 0 ]; then
        echo "No Verifier contracts with new signature found automatically."
        echo "Please run with specific file paths:"
        echo "Usage: $0 <input_file> <output_file>"
        return 1
    fi
    
    echo "Found ${#found_files[@]} Verifier contract(s) to convert:"
    for file in "${found_files[@]}"; do
        echo "  - $file"
    done
    
    # Convert each found file
    for file in "${found_files[@]}"; do
        local dir=$(dirname "$file")
        local basename=$(basename "$file" .sol)
        
        # Generate output filename based on input filename
        # If it contains "Enygma", keep that pattern, otherwise add "Enygma" prefix
        if [[ "$basename" == *"Enygma"* ]]; then
            local output_file="$dir/${basename}_converted.sol"
        elif [[ "$basename" == *"Erc"* ]]; then
            local output_file="$dir/${basename}_converted.sol" 
        else
            local output_file="$dir/Enygma${basename}_converted.sol"
        fi
        convert_verifier "$file" "$output_file"
    done
}

# Function to check if a file needs conversion
needs_conversion() {
    local file="$1"
    
    echo "Checking if $file needs conversion..."
    
    # Check if it has contract Verifier and the new signature but not the old one
    if grep -q "contract Verifier" "$file"; then
        echo "  -> Found contract Verifier, checking function signature..."
        
        # Check for new signature (multi-line aware)
        local has_new_sig=false
        if grep -A5 "function verifyProof" "$file" | grep -q "uint256\[8\]" ||
           (grep -A5 "function verifyProof" "$file" | grep -q "proof" && 
            grep -A5 "function verifyProof" "$file" | grep -q "input"); then
            has_new_sig=true
        fi
        
        # Check for old signature
        local has_old_sig=false
        if grep -A5 "function verifyProof" "$file" | grep -q "_pA.*_pB.*_pC"; then
            has_old_sig=true
        fi
        
        if [ "$has_new_sig" = true ] && [ "$has_old_sig" = false ]; then
            echo "  -> File needs conversion (has contract Verifier with new signature, missing old signature)"
            return 0  # needs conversion
        else
            echo "  -> File doesn't need conversion (has_new_sig=$has_new_sig, has_old_sig=$has_old_sig)"
        fi
    else
        echo "  -> Not a Verifier contract"
    fi
    
    echo "  -> Current contract and verifyProof signatures:"
    grep -n "^contract " "$file" || echo "  -> No contracts found"
    echo "  -> Function signature (next 5 lines after 'function verifyProof'):"
    grep -A5 "function verifyProof" "$file" || echo "  -> No verifyProof function found"
    return 1  # doesn't need conversion
}

# Main script logic
case $# in
    0)
        # Auto-detect mode
        find_and_convert_verifiers
        ;;
    1)
        if [ "$1" = "debug" ]; then
            # Debug mode - show what's in the files
            echo "=== DEBUG MODE ==="
            for path in "./last_build" "./contracts" "./src" "./generated" "."; do
                if [ -d "$path" ]; then
                    echo ""
                    echo "=== Files in $path ==="
                    find "$path" -name "*.sol" 2>/dev/null | while read file; do
                        echo "File: $file"
                        if [ -f "$file" ]; then
                            echo "  Contract names:"
                            grep "^contract " "$file" || echo "    No contracts found"
                            echo "  VerifyProof functions:"
                            grep -n "function verifyProof" "$file" || echo "    No verifyProof functions found"
                            echo "  Needs conversion?"
                            if grep -q "contract Verifier" "$file"; then
                                local has_new_sig=false
                                if grep -A5 "function verifyProof" "$file" | grep -q "uint256\[8\]" ||
                                   (grep -A5 "function verifyProof" "$file" | grep -q "proof" && 
                                    grep -A5 "function verifyProof" "$file" | grep -q "input"); then
                                    has_new_sig=true
                                fi
                                
                                local has_old_sig=false
                                if grep -A5 "function verifyProof" "$file" | grep -q "_pA.*_pB.*_pC"; then
                                    has_old_sig=true
                                fi
                                
                                if [ "$has_new_sig" = true ] && [ "$has_old_sig" = false ]; then
                                    echo "    YES - has contract Verifier with new signature"
                                else
                                    echo "    NO - has_new_sig=$has_new_sig, has_old_sig=$has_old_sig"
                                fi
                            else
                                echo "    NO - not a Verifier contract"
                            fi
                            echo "  Full function signature:"
                            grep -A10 "function verifyProof" "$file" | head -8 || echo "    No verifyProof function found"
                            echo ""
                        fi
                    done
                fi
            done
            exit 0
        else
            # Single file - convert in place with backup
            input_file="$1"
            if [ ! -f "$input_file" ]; then
                echo "Error: Input file '$input_file' does not exist"
                exit 1
            fi
            
            if needs_conversion "$input_file"; then
                backup_file="${input_file}.backup"
                cp "$input_file" "$backup_file"
                echo "Created backup: $backup_file"
                convert_verifier "$input_file" "$input_file"
            else
                echo "File $input_file doesn't appear to need conversion (already has old signature or missing new signature)"
            fi
        fi
        ;;
    2)
        # Manual file specification
        if [ ! -f "$1" ]; then
            echo "Error: Input file '$1' does not exist"
            exit 1
        fi
        convert_verifier "$1" "$2"
        ;;
    *)
        echo "Usage: $0 [input_file] [output_file]"
        echo ""
        echo "Options:"
        echo "  No arguments: Auto-detect and convert verifier contracts"
        echo "  One argument: Convert file in-place (creates backup)"
        echo "  Two arguments: Convert specific input file to output file"
        echo "  debug: Show debug information about all found verifier files"
        exit 1
        ;;
esac

echo ""
echo "✅ Verifier conversion process completed!"
echo ""
echo "The converted contract will have:"
echo "  - Contract name: Based on filename "  
echo "  - Function signature: verifyProof(uint[2] _pA, uint[2][2] _pB, uint[2] _pC, uint[n] _pubSignals)"
echo "  - Return type: bool (true for valid proof, false for invalid)"
echo "  - Original function renamed to: verifyProofInternal"
echo ""

echo ""