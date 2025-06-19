import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

new_zkp_file_path = './evaluation/ZKP_performance_data.csv'
new_he_file_path = './evaluation/HE_performance_data.csv'
original_he_file_path = './evaluation/HE_performance_data_orig.csv'
rust_he_file_path = './evaluation/HE_performance_data_rs.csv'

new_zkp_data = pd.read_csv(new_zkp_file_path)
new_he_data = pd.read_csv(new_he_file_path)
original_he_data = pd.read_csv(original_he_file_path)
rust_he_data = pd.read_csv(rust_he_file_path)
print(rust_he_data.columns.tolist())

# Extract relevant columns for comparison
new_zkp_metrics = new_zkp_data[['generateZKPCPU', 'generateZKPMemory', 'generateZKPDuration',
                                'verifyZKPCPU', 'verifyZKPMemory', 'verifyZKPDuration']]

new_he_metrics = new_he_data[['verifierSetUpCPU', 'verifierSetUpMemory', 'verifierSetUpTime',
                              'proverCPU', 'proverMemory', 'proverTime',
                              'verifierVerifyCPU', 'verifierVerifyMemory', 'verifierVerifyTime']]


original_he_metrics = original_he_data[['verifierSetUpCPU', 'verifierSetUpMemory', 'verifierSetUpTime',
                              'proverCPU', 'proverMemory', 'proverTime',
                              'verifierVerifyCPU', 'verifierVerifyMemory', 'verifierVerifyTime']]

rust_he_metrics = rust_he_data[['verifierSetUpCPU', 'verifierSetUpMemory', 'verifierSetUpTime',
                              'proverCPU', 'proverMemory', 'proverTime',
                              'verifierVerifyCPU', 'verifierVerifyMemory', 'verifierVerifyTime']]

# Rename columns for better comparison
new_zkp_metrics.columns = ['GenCPU', 'GenMemory', 'GenDuration', 'VerCPU', 'VerMemory', 'VerDuration']

new_he_metrics.columns = ['SetupCPU', 'SetupMemory', 'SetupDuration',
                          'CalculationCPU', 'CalculationMemory', 'CalculationDuration',
                          'VerificationCPU', 'VerificationMemory', 'VerificationDuration']

original_he_metrics.columns = ['SetupCPU', 'SetupMemory', 'SetupDuration',
                          'CalculationCPU', 'CalculationMemory', 'CalculationDuration',
                          'VerificationCPU', 'VerificationMemory', 'VerificationDuration']

rust_he_metrics.columns = ['SetupCPU', 'SetupMemory', 'SetupDuration',
                          'CalculationCPU', 'CalculationMemory', 'CalculationDuration',
                          'VerificationCPU', 'VerificationMemory', 'VerificationDuration']

x_labels = ['ZKP Generation', 'ZKP Verification', 'HE Setup', 'HE Calculation', 'HE Verification']

def filter_non_zero(data):
    return [value for value in data if value > 0]

def plot_comparison_box(data, labels, title, y_label, filename, unit):

    fig, ax = plt.subplots(figsize=(10, 8))

    # Fill the outlier dots with blue and make them smaller
    flierprops = dict(marker='o', color='red', markersize=4, markerfacecolor='red')
    ax.boxplot(data, labels=labels, flierprops=flierprops)

    # ax.bar(data)

    ax.set_title(title)
    ax.set_ylabel(y_label)
    ax.set_ylim(bottom=0)
    ax.grid(axis='y', linestyle=':', linewidth=0.5)  # add dotted horizontal grid lines

    # Increase the number of y-axis ticks
    y_ticks = ax.get_yticks()
    new_y_ticks = []
    for i in range(1, len(y_ticks)):
        new_y_ticks.append(y_ticks[i - 1])
        new_y_ticks.append((y_ticks[i - 1] + y_ticks[i]) / 2)
    new_y_ticks.append(y_ticks[-1])
    ax.set_yticks(new_y_ticks)

    # Calculate statistics
    max_vals = [np.max(d) for d in data]
    avg_vals = [np.mean(d) for d in data]
    med_vals = [np.median(d) for d in data]
    min_vals = [np.min(d) for d in data]


    plt.subplots_adjust(left=0.2, bottom=0.4)
    plt.tight_layout(rect=[0.02, 0.1, 1, 0.95])
    plt.savefig(f"./evaluation/{filename}.png")
    plt.show()

data_dict = {
    "cpu": {
        "data": [
            filter_non_zero(new_zkp_metrics['GenCPU']), filter_non_zero(new_zkp_metrics['VerCPU']), 
            filter_non_zero(original_he_metrics['SetupCPU']), filter_non_zero(original_he_metrics['CalculationCPU']),
            filter_non_zero(original_he_metrics['VerificationCPU']),
            filter_non_zero(new_he_metrics['SetupCPU']), filter_non_zero(new_he_metrics['CalculationCPU']),
            filter_non_zero(new_he_metrics['VerificationCPU'])],
        "labels": x_labels,
        "title": 'CPU Usage',
        "y_label": 'CPU Usage (%)',
        "filename": 'cpu_usage_comparison',
        "unit": '%'
    },
    "memory": {
        "data": [
            new_zkp_metrics['GenMemory'], new_zkp_metrics['VerMemory'],
            original_he_metrics['SetupMemory'], original_he_metrics['CalculationMemory'], original_he_metrics['VerificationMemory'],
            new_he_metrics['SetupMemory'], new_he_metrics['CalculationMemory'], new_he_metrics['VerificationMemory']],
        "labels": x_labels,
        "title": 'Memory Usage',
        "y_label": 'Memory Usage (MB)',
        "filename": 'memory_usage_comparison',
        "unit": 'MB'
    },
    "time": {
        "data": [
            new_zkp_metrics['GenDuration'], new_zkp_metrics['VerDuration'],
            original_he_metrics['SetupDuration'], original_he_metrics['CalculationDuration'], original_he_metrics['VerificationDuration'],
            new_he_metrics['SetupDuration'], new_he_metrics['CalculationDuration'], new_he_metrics['VerificationDuration']],
        "labels": x_labels,
        "title": 'Time Performance',
        "y_label": 'Duration (ms)',
        "filename": 'duration_comparison',
        "unit": 'ms'
    },
}

def get_average(data):
    avg_zkp_gen = [np.mean(d) for d in data[0]]
    avg_zkp_ver = [np.mean(d) for d in data[1]]
    avg_zkp = np.concatenate((avg_zkp_gen, avg_zkp_ver), axis=None)
    avg_zkp_mean = np.mean(avg_zkp)

    avg_orig_he_gen = [np.mean(d) for d in data[2]]
    avg_orig_he_cal = [np.mean(d) for d in data[3]]
    avg_orig_he_ver = [np.mean(d) for d in data[4]]
    avg_orig_he = np.concatenate((avg_orig_he_gen, avg_orig_he_cal, avg_orig_he_ver), axis=None)
    avg_orig_he_mean = np.mean(avg_orig_he)

    avg_new_he_gen = [np.mean(d) for d in data[5]]
    avg_new_he_cal = [np.mean(d) for d in data[6]]
    avg_new_he_ver = [np.mean(d) for d in data[7]]
    avg_new_he = np.concatenate((avg_new_he_gen, avg_new_he_cal, avg_new_he_ver), axis=None)
    avg_new_he_mean = np.mean(avg_new_he)

    return [avg_zkp_mean, avg_orig_he_mean, avg_new_he_mean]

# CPU plot
# y-axis: percentage range
# x-axis: ZKP, HE
# plot average CPU usage

# Memory plot
# y-axis: MB / megabytes
# x-axis: ZKP, HE
# plot average memory

# Time plot
# y-axis: ms / milliseconds
# x-axis: ZKP, HE
# plot average time
def plot_comparison_bar(data, labels, title, y_label, filename, unit):

    cpu_data = get_average(data_dict['cpu']['data'])
    memory_data = get_average(data_dict['memory']['data'])
    time_data = get_average(data_dict['time']['data'])

    data = [cpu_data, memory_data, time_data]
    labels = ['ZKP', 'Orig.\n HE', 'Comp.\n HE']

    titles = [data_dict['cpu']['title'], data_dict['memory']['title'], data_dict['time']['title']]
    y_labels = [data_dict['cpu']['y_label'], data_dict['memory']['y_label'], data_dict['time']['y_label']]

    # # print('zkp average:', avg_zkp_mean, unit)
    # # print(' he average:', avg_he_mean, unit)

    # figsize = (width, height)
    fig, ax = plt.subplots(1, 3, figsize=(8, 4), layout='compressed')

    # # x-axis, y-axis, labels

    # ax.bar(labels_, data_, width=0.2)

    # for i, v in enumerate(data_):
    #     plt.text(labels_[i], round(data_[i], 2) + 1.5, str(round(v, 2)), horizontalalignment="center")

    fig.suptitle("Average Performance Comparison")
    # ax.set_title(title)
    # ax.set_xlabel('Privacy Mechanism')
    # ax.set_ylabel(y_label)

    width = 0.6

    for i in range(3):
        ax[i].bar(labels, data[i], width=width, color='#069AF3')
        for j, v in enumerate(data[i]):
            if (i == 0):
                ax[i].text(labels[j], round(v, 2) + 1, str(round(v, 2)), fontsize=8, horizontalalignment="center")
            else:
                ax[i].text(labels[j], round(v, 2) + 10, str(round(v, 2)), fontsize=8, horizontalalignment="center")
        ax[i].set_title(titles[i], fontsize=10)
        ax[i].set_ylabel(y_labels[i])
        ax[i].set_xlim(-1 + width / 3, 3 - width / 3 )

    plt.savefig(f"./evaluation/{filename}.png")
    plt.show()



# CPU Usage Comparison (filter out 0 values)
plot_comparison_box(
    [filter_non_zero(new_zkp_metrics['GenCPU']), filter_non_zero(new_zkp_metrics['VerCPU']),
     filter_non_zero(new_he_metrics['SetupCPU']), filter_non_zero(new_he_metrics['CalculationCPU']), filter_non_zero(new_he_metrics['VerificationCPU'])],
     x_labels,
     'CPU Usage per Function',
     'CPU Usage (%)',
     'ZKP_cpu_usage_comparison',
     '%'
)

# plot_comparison_bar(
#     [filter_non_zero(new_zkp_metrics['GenCPU']), filter_non_zero(new_zkp_metrics['VerCPU']),
#      filter_non_zero(new_he_metrics['SetupCPU']), filter_non_zero(new_he_metrics['CalculationCPU']),
#      filter_non_zero(new_he_metrics['VerificationCPU'])],
#      x_labels,
#      'CPU Usage',
#      'CPU Usage (%)',
#      'cpu_usage_comparison',
#      '%'
# )

# Memory Usage Comparison
plot_comparison_box(
    [new_zkp_metrics['GenMemory'], new_zkp_metrics['VerMemory'], new_he_metrics['SetupMemory'],
     new_he_metrics['CalculationMemory'], new_he_metrics['VerificationMemory']],
    x_labels,
    'Memory Usage per Function',
    'Memory Usage (MB)',
    'ZKP_memory_usage_comparison',
    'MB'
)

# Memory Usage Comparison
# plot_comparison_bar(
#     [new_zkp_metrics['GenMemory'], new_zkp_metrics['VerMemory'],
#      new_he_metrics['SetupMemory'], new_he_metrics['CalculationMemory'], new_he_metrics['VerificationMemory']],
#      x_labels,
#      'Memory Usage',
#      'Memory Usage (MB)',
#      'memory_usage_comparison',
#      'MB'
# )

# Duration Comparison
plot_comparison_box(
    [new_zkp_metrics['GenDuration'], new_zkp_metrics['VerDuration'], new_he_metrics['SetupDuration'],
     new_he_metrics['CalculationDuration'], new_he_metrics['VerificationDuration']],
    x_labels,
    'Duration per Function',
    'Duration (ms)',
    'ZKP_duration_comparison',
    'ms'
)

# Duration Comparison
# plot_comparison_bar(
#     [new_zkp_metrics['GenDuration'], new_zkp_metrics['VerDuration'],
#      new_he_metrics['SetupDuration'], new_he_metrics['CalculationDuration'], new_he_metrics['VerificationDuration']],
#      x_labels,
#      'Time Performance',
#      'Duration (ms)',
#      'duration_comparison',
#      'ms'
# )


# comparison with original HE implementation
x_labels = ['Original \nHE Setup', 'Original \nHE Calculation', 'Original \nHE Verification', 'Comparison \nHE Setup', 'Comparison \nHE Calculation', 'Comparison \nHE Verification']

plot_comparison_box(
    [filter_non_zero(original_he_metrics['SetupCPU']), filter_non_zero(original_he_metrics['CalculationCPU']), filter_non_zero(original_he_metrics['VerificationCPU']),
     filter_non_zero(new_he_metrics['SetupCPU']), filter_non_zero(new_he_metrics['CalculationCPU']), filter_non_zero(new_he_metrics['VerificationCPU'])],
     x_labels,
     'CPU Usage per Function',
     'CPU Usage (%)',
     'original_cpu_usage_comparison',
     '%'
)

plot_comparison_box(
    [original_he_metrics['SetupMemory'], original_he_metrics['CalculationMemory'], original_he_metrics['VerificationMemory'], new_he_metrics['SetupMemory'], new_he_metrics['CalculationMemory'], new_he_metrics['VerificationMemory']],
    x_labels,
    'Memory Usage per Function',
    'Memory Usage (MB)',
    'original_memory_usage_comparison',
    'MB'
)

plot_comparison_box(
    [original_he_metrics['SetupDuration'], original_he_metrics['CalculationDuration'], original_he_metrics['VerificationDuration'], new_he_metrics['SetupDuration'],
     new_he_metrics['CalculationDuration'], new_he_metrics['VerificationDuration']],
    x_labels,
    'Duration per Function',
    'Duration (ms)',
    'original_duration_comparison',
    'ms'
)

x_labels = ['Rust comp. \nHE Setup', 'Rust comp. \nHE Calculation', 'Rust comp. \nHE Verification', 'Comparison \nHE Setup', 'Comparison \nHE Calculation', 'Comparison \nHE Verification']

plot_comparison_box(
    [filter_non_zero(rust_he_metrics['SetupCPU']), filter_non_zero(rust_he_metrics['CalculationCPU']), filter_non_zero(rust_he_metrics['VerificationCPU']),
     filter_non_zero(new_he_metrics['SetupCPU']), filter_non_zero(new_he_metrics['CalculationCPU']), filter_non_zero(new_he_metrics['VerificationCPU'])],
     x_labels,
     'CPU Usage per Function',
     'CPU Usage (%)',
     'rust_cpu_usage_comparison',
     '%'
)

plot_comparison_box(
    [rust_he_metrics['SetupMemory'], rust_he_metrics['CalculationMemory'], rust_he_metrics['VerificationMemory'], new_he_metrics['SetupMemory'], new_he_metrics['CalculationMemory'], new_he_metrics['VerificationMemory']],
    x_labels,
    'Memory Usage per Function',
    'Memory Usage (MB)',
    'rust_memory_usage_comparison',
    'MB'
)

plot_comparison_box(
    [rust_he_metrics['SetupDuration'], rust_he_metrics['CalculationDuration'], rust_he_metrics['VerificationDuration'], new_he_metrics['SetupDuration'],
     new_he_metrics['CalculationDuration'], new_he_metrics['VerificationDuration']],
    x_labels,
    'Duration per Function',
    'Duration (ms)',
    'rust_duration_comparison',
    'ms'
)