
import kagglehub
import pandas as pd
import os

def explore_dataset():
    print("Downloading/Loading dataset...")
    path = kagglehub.dataset_download("himadri07/ciciot2023")
    print(f"Dataset downloaded to: {path}")

    # Path found from investigation
    csv_path = os.path.join(path, "CICIOT23", "train", "train.csv")
    print(f"\nLoading file: {csv_path}")
    
    if not os.path.exists(csv_path):
        print("File not found! listing recursive...")
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".csv"):
                    print(os.path.join(root, file))
        return

    # Read only first 100k rows to be fast
    df = pd.read_csv(csv_path, nrows=100000)

    print(f"\nShape (first 100k): {df.shape}")
    print("\nColumns:")
    print(df.columns.tolist())

    print("\nNull values:")
    print(df.isnull().sum().sum())

    print("\nLabel distribution:")
    if 'label' in df.columns:
        print(df['label'].value_counts())
    else:
        # Sometimes label column has different name or casing
        print("No 'label' column found! Checking for similar...")
        for col in df.columns:
            if 'label' in col.lower() or 'class' in col.lower():
                print(f"Found potential label column: {col}")
                print(df[col].value_counts())

if __name__ == "__main__":
    explore_dataset()
