import ipaddress
import pandas as pd
import numpy as np
from sklearn.impute import SimpleImputer

def process_traffic_data(input_file, output_file):
    # Set up the SimpleImputer
    imputer = SimpleImputer(strategy='mean')

    # Initialize a flag to check if the output file already exists (for appending data)
    is_first_chunk = True

    # Define a function to process each chunk
    def process_chunk(df):
        # Map protocol names to integers (TCP = 6, UDP = 17)
        protocol_map = {'TCP': 6, 'UDP': 17}
        df['Protocol'] = df['Protocol'].map(protocol_map).astype('Int64')

        # Remove any extra spaces in column names
        df.columns = df.columns.str.strip()

        # Convert 'Source IP' and 'Destination IP' to integers using IP address conversion
        def safe_ip_conversion(ip):
            try:
                return int(ipaddress.IPv4Address(ip))
            except ValueError:
                return np.nan  # Return NaN if the IP is invalid

        df['Source IP'] = df['Source IP'].apply(safe_ip_conversion)
        df['Destination IP'] = df['Destination IP'].apply(safe_ip_conversion)

        # Convert 'Timestamp' to datetime format and then to Unix timestamp
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df['Timestamp'] = df['Timestamp'].apply(lambda x: x.timestamp() if pd.notnull(x) else np.nan)

        # Replace infinite values with NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Impute missing numerical values using the mean of the column
        numerical_columns = df.select_dtypes(include=['float64', 'int64']).columns
        df[numerical_columns] = imputer.fit_transform(df[numerical_columns])

        return df
    chunk_size = 500
    for chunk in pd.read_csv(input_file, chunksize=chunk_size):
        processed_chunk = process_chunk(chunk)
        print("first iteration is finished")

        # Append to the output CSV file (create file if it doesn't exist)
        if is_first_chunk:
            processed_chunk.to_csv(output_file, index=False, mode='w')
            is_first_chunk = False
        else:
            processed_chunk.to_csv(output_file, index=False, mode='a', header=False)

    print(f"Processed data saved to {output_file}")

# Call the function with the desired input and output filenames
process_traffic_data('captured_traffic.csv', 'captured_dataset1.csv')
