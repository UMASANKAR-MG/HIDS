import logging
import RandomForest
import network
import capture_preprocess
import system_usage
import windows_logs
import checknet

# Set up logging configuration
logging.basicConfig(level=logging.INFO, filename='process.log', filemode='w')
def main():
    while True:
        try:
                logging.info("Starting network packet capture.")
                network.capture_packets()
            
                logging.info("Processing traffic data.")
                capture_preprocess.process_traffic_data('captured_traffic.csv', 'captured_dataset.csv')
                logging.info("Training Random Forest model and predicting network traffic.")
                RandomForest.train_and_predict_network_traffic(
                    train_file='network_dataset.csv',
                    new_data_file='captured_dataset.csv',
                    output_model_file='random_forest_model.joblib',
                    output_scaler_file='scaler.joblib',
                    prediction_output_file='predicted_captured_dataset.csv'
                )
                logging.info("Model training and prediction completed.")
        except Exception as e:
            logging.error(f"An error occurred in the main: {e}")

if __name__ == "__main__":
    if checknet.net():
        try:
           main()
        except KeyboardInterrupt:
            logging.info("Program interrupted by the user.")
    else:
        logging.error("Network is not available.")
