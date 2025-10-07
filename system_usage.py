import psutil
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from collections import deque

def monitor_system(threshold=90, plot_duration=60):
    # Data collections for plotting
    data_buffers = {
        'cpu': deque([0] * plot_duration, maxlen=plot_duration),
        'memory': deque([0] * plot_duration, maxlen=plot_duration),
        'disk': deque([0] * plot_duration, maxlen=plot_duration),
        'net_sent': deque([0] * plot_duration, maxlen=plot_duration),
        'net_recv': deque([0] * plot_duration, maxlen=plot_duration)
    }

    # Initialize network counters
    initial_network_stats = psutil.net_io_counters()
    initial_bytes_sent = initial_network_stats.bytes_sent
    initial_bytes_recv = initial_network_stats.bytes_recv

    # Set up the figure and subplots
    fig, axs = plt.subplots(4, 1, figsize=(10, 8))
    plt.subplots_adjust(hspace=0.5)

    def add_alert_text(ax, message):
        """Adds an alert text to the plot when threshold is exceeded."""
        ax.text(0.5, 0.5, message, transform=ax.transAxes, fontsize=12,
                color="red", fontweight="bold", ha="center", va="center", alpha=0.7)

    def plot_metric(ax, data, title, ylabel, color, threshold_exceeded, alert_message):
        """Generalized plotting function for updating and displaying system metrics."""
        ax.clear()
        ax.plot(data, color=color)
        ax.set_ylim(0, 100)
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        if threshold_exceeded:
            add_alert_text(ax, alert_message)

    def update_data(_):
        # Update CPU usage
        cpu_usage = psutil.cpu_percent(interval=None)
        data_buffers['cpu'].append(cpu_usage)
        plot_metric(
            axs[0], data_buffers['cpu'], "CPU Usage", "Usage (%)",
            "tab:red" if cpu_usage >= threshold else "tab:blue",
            cpu_usage >= threshold, "ALERT: CPU Usage High!"
        )
        print(f"CPU Usage: {cpu_usage}%")

        # Update memory usage
        memory_percentage = psutil.virtual_memory().percent
        data_buffers['memory'].append(memory_percentage)
        plot_metric(
            axs[1], data_buffers['memory'], "Memory Usage", "Usage (%)",
            "tab:red" if memory_percentage >= threshold else "tab:orange",
            memory_percentage >= threshold, "ALERT: Memory Usage High!"
        )
        print(f"Memory Usage: {memory_percentage}%")

        # Update disk usage
        disk_percentage = psutil.disk_usage('/').percent
        data_buffers['disk'].append(disk_percentage)
        plot_metric(
            axs[2], data_buffers['disk'], "Disk Usage", "Usage (%)",
            "tab:red" if disk_percentage >= threshold else "tab:green",
            disk_percentage >= threshold, "ALERT: Disk Usage High!"
        )
        print(f"Disk Usage: {disk_percentage}%")

        # Update network usage
        network_stats = psutil.net_io_counters()
        bytes_sent = (network_stats.bytes_sent - initial_bytes_sent) / (1024 * 1024)  # MB
        bytes_recv = (network_stats.bytes_recv - initial_bytes_recv) / (1024 * 1024)  # MB
        data_buffers['net_sent'].append(bytes_sent)
        data_buffers['net_recv'].append(bytes_recv)
        axs[3].clear()
        axs[3].plot(data_buffers['net_sent'], label="Bytes Sent (MB)", color="tab:blue")
        axs[3].plot(data_buffers['net_recv'], label="Bytes Received (MB)", color="tab:purple")
        axs[3].set_title("Network Usage")
        axs[3].set_ylabel("Data (MB)")
        axs[3].legend(loc="upper right")
        if bytes_sent >= threshold or bytes_recv >= threshold:
            add_alert_text(axs[3], "ALERT: High Network Traffic!")
        
        print(f"Network Sent: {bytes_sent:.2f} MB, Received: {bytes_recv:.2f} MB")


    anim = animation.FuncAnimation(fig, update_data, interval=1000, cache_frame_data=False)
    plt.show()
monitor_system()

