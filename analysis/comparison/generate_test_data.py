import os

def generate_text_file(filename, size_kb):
    """Generates a dummy text file of approximately `size_kb` KB."""
    # A standard page is around 3KB of text
    content = "This is a dummy text to simulate document content for the crypto benchmark. " * 40
    # Each repetition is ~74 bytes. We need to reach size_kb * 1024 bytes.
    target_bytes = size_kb * 1024
    
    with open(filename, 'w') as f:
        bytes_written = 0
        while bytes_written < target_bytes:
            f.write(content)
            bytes_written += len(content)
            
    print(f"Generated {filename} ({os.path.getsize(filename) / 1024:.2f} KB)")

def generate_image_file(filename, size_kb=1024):
    """Generates a dummy image file (raw bytes)."""
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_kb * 1024))
    print(f"Generated {filename} ({os.path.getsize(filename) / 1024:.2f} KB)")

if __name__ == '__main__':
    # Ensure test_data directory exists
    os.makedirs('test_data', exist_ok=True)
    
    # Generate 1-page text file (~3KB)
    generate_text_file('test_data/1_page.txt', 3)
    
    # Generate 10-page text file (~30KB)
    generate_text_file('test_data/10_page.txt', 30)
    
    # Generate 50-page text file (~150KB)
    generate_text_file('test_data/50_page.txt', 150)
    
    # Generate 500-page text file (~1500KB)
    generate_text_file('test_data/500_page.txt', 1500)
    
    # Generate an image file (~20KB depending on compression)
    generate_image_file('test_data/sample_image.jpg')
    
    print("Test data generation complete.")
