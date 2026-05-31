import os
import pandas as pd
import matplotlib.pyplot as plt

def generate_plots():
    csv_file = 'benchmark_results.csv'
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found. Run benchmark.py first.")
        return

    df = pd.read_csv(csv_file)
    # df has a row for each algorithm for each file size
    # We want to group by Algorithm and take the mean across different file sizes for KeyGen and KeyEx
    # since they are constant in Hybrid Encryption.
    # For Enc and Dec, it scales, so we can plot time vs file size!

    # Create an output directory for graphs
    os.makedirs('graphs', exist_ok=True)
    
    # 1. Bar chart for Key Generation & Key Exchange (Average)
    avg_times = df.groupby('Algo')[['KeyGen(s)', 'KeyEx(s)']].mean().reset_index()
    
    fig, ax = plt.subplots(figsize=(8, 6))
    x = range(len(avg_times))
    width = 0.35
    
    ax.bar([i - width/2 for i in x], avg_times['KeyGen(s)'], width, label='Key Generation')
    ax.bar([i + width/2 for i in x], avg_times['KeyEx(s)'], width, label='Key Exchange')
    
    ax.set_ylabel('Time (seconds)')
    ax.set_title('Average Asymmetric Overhead (KeyGen & KeyEx)')
    ax.set_xticks(x)
    ax.set_xticklabels(avg_times['Algo'])
    ax.legend()
    plt.yscale('log') # Use log scale because ECC is much faster than others
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig('graphs/key_operations_log_scale.png')
    plt.close()

    # 2. Key Size comparison
    key_sizes = df.groupby('Algo')['KeySize(B)'].mean().reset_index()
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.bar(key_sizes['Algo'], key_sizes['KeySize(B)'], color=['#ff9999','#66b3ff','#99ff99'])
    ax.set_ylabel('Key Size (Bytes)')
    ax.set_title('Public Key Size Comparison')
    for i, v in enumerate(key_sizes['KeySize(B)']):
        ax.text(i, v + 5, str(int(v)), ha='center')
    plt.tight_layout()
    plt.savefig('graphs/key_sizes.png')
    plt.close()
    
    print("Graphs generated successfully in 'graphs/' directory.")

if __name__ == '__main__':
    # Change dir to analysis/comparison so paths work
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    generate_plots()
