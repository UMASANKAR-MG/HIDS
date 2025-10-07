import pandas as pd
from joblib import dump, load
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

def train_and_predict_network_traffic(train_file, new_data_file, output_model_file, output_scaler_file, prediction_output_file):

    df = pd.read_csv(train_file)
    df.dropna(inplace=True) 

    X = df.drop(columns=['Label']).values 
    y = df['Label'].values 

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        max_features='sqrt',
        min_samples_split=2,
        random_state=42
    )
    clf.fit(X_train, y_train)

    dump(clf, output_model_file)
    dump(scaler, output_scaler_file)

    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    #classification_rep = classification_report(y_test, y_pred)
    print("Accuracy:", accuracy)
    #print("Classification Report:\n", classification_rep)

    new_data = pd.read_csv(new_data_file)
    new_data.dropna(inplace=True)

    train_columns = df.drop(columns=['Label']).columns
    new_data = new_data[train_columns]

    new_data_scaled = scaler.transform(new_data)

    new_predictions = clf.predict(new_data_scaled)
    new_data['Predicted_Label'] = new_predictions

    filtered_predictions = new_data[new_data['Predicted_Label'] == 1]
    filtered_predictions.to_csv(prediction_output_file, index=False)
    print(f"Filtered predictions have been saved to {prediction_output_file}")

    def alert_animation():
        fig, ax = plt.subplots(figsize=(10, 6))
        counts, bins, patches = ax.hist(new_data['Predicted_Label'], bins=2, rwidth=0.8, color='grey')
        ax.set_title("Distribution of Predicted Labels")
        ax.set_xlabel("Predicted Label")
        ax.set_ylabel("Frequency")
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Label 0", "Label 1"])
        
        if (new_data['Predicted_Label'] == 1).any():
            alert_text = ax.text(0.5, 0.8, "ALERT: Detected malicious", transform=ax.transAxes,
                                fontsize=16, color='red', ha='center', va='center', fontweight='bold',
                                visible=False)
            
            def animate(frame):
                color = 'red' if frame % 2 == 0 else 'grey' 
                for patch in patches:
                    patch.set_color(color)
                alert_text.set_visible(True)

            ani = FuncAnimation(fig, animate, repeat=False, interval=500)
        else:
            for patch in patches:
                patch.set_color('skyblue')
        
        plt.show()

    alert_animation()



