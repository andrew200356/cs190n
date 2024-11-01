import subprocess, os, sys, json, time, datetime, re, csv, random, string, math, copy, shutil, scipy
import pandas as pd
from multiprocessing import Pool
import numpy as np 
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.ticker import ScalarFormatter
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
from datetime import timedelta, datetime
from scapy.all import rdpcap
import matplotlib.dates as mdates
from matplotlib.ticker import MultipleLocator

def setup_plot(y_limits=None):
    """Set up the plot with common settings."""
    fig = plt.figure(figsize=(10, 5)) 
    ax = plt.gca()
    fig.fontsize = 12
    plt.tight_layout()
    ax.grid(True)
    # ax.xaxis.set_major_locator(MultipleLocator(2))
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x)}'))
    
    if y_limits is not None:
        ax.set_ylim(y_limits)
    
    return ax


def analyzePcap(pcap_file):
    """
    Get the pcap file as input and return the throughput data, time intervals, average throughput and burstiness
    """
    print('Analyzing pcap file:', pcap_file)
    packets = rdpcap(pcap_file)

    # Initialize variables to store throughput data
    interval_duration = 0.1  # 100ms intervals
    time_intervals = []
    throughput_data = []
    total_bytes = 0
    start_time = None
    current_interval_start = None
    # Calculate throughput in 100ms intervals
    for packet in packets:
        if packet.haslayer('IP'):
            packet_size = len(packet)
            packet_time = datetime.fromtimestamp(float(packet.time))  # Ensure packet.time is a float

            if start_time is None:
                start_time = packet_time
                current_interval_start = start_time

            # Check if the packet belongs to the current interval
            if (packet_time - current_interval_start).total_seconds() < interval_duration:
                total_bytes += packet_size
            
            else:
                # Calculate throughput for the current interval
                throughput_mbps = (total_bytes * 8) / (interval_duration * 1e6)  # Convert bytes to bits, then to Mbps
                time_intervals.append(current_interval_start)
                throughput_data.append(throughput_mbps)

                # Reset for the next interval
                current_interval_start += timedelta(seconds=interval_duration)
                total_bytes = packet_size
                
    avg_throughput = np.mean(throughput_data) 
    print('Average throughput:', avg_throughput, 'Mbps')
    # get the ration of 95th percentile to the average throughput
    percentile_95 = np.percentile(throughput_data, 95)
    burstiness = percentile_95/avg_throughput
    print('burstiness :', burstiness)
    return [throughput_data, time_intervals, avg_throughput, burstiness]


def load_throughput_data(input_dir, filename, start_time, end_time):
    # Check if the analyzed data is already stored in the input directory
    if os.path.exists(input_dir + filename + '_analyzed_data.json'):
        with open(input_dir + filename + '_analyzed_data.json', 'r') as f:
            throughput_data = json.load(f)
            return throughput_data['throughput'], throughput_data['time'], throughput_data['average_throughput'], throughput_data['burstiness']
    
    # Read the pcap file and analyze throughput and time
    throughput, time, average_throughput, burstiness = analyzePcap(input_dir + filename)
    # Shift the time to start from the video start time and change the time to
    start_time = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f")
    end_time = datetime.strptime(str(end_time), "%Y-%m-%d %H:%M:%S.%f")
    # Get the duration in seconds from the start time to the end time
    duration = (end_time - start_time).total_seconds()
    time = [(t - start_time).total_seconds() for t in time]
    
    # Remove the times which the values are less than 0, and remove the corresponding values from the throughput in which the time is less than 0
    time = [time[i] for i in range(len(time)) if time[i] >= 0 and time[i] <= duration]
    throughput = throughput[len(throughput) - len(time):]
    
    # store throughput, time, average throughput and burstiness in a dictionary as json file in the same input directory
    throughput_data = {'throughput': throughput, 'time': time, 'average_throughput': average_throughput, 'burstiness': burstiness}
    with open(input_dir + filename + '_analyzed_data.json', 'w') as f:
        json.dump(throughput_data, f)
    return throughput, time, average_throughput, burstiness



def load_log_files(input_dir):
    # load the puffer log files 
    video_sent = pd.read_csv(f'{input_dir}video_sent.1.log', header=None)
    # video_sent,channel={1},server_id={2} expt_id={3}i,user="{4}",first_init_id={5}i,init_id={6}i,video_ts={7}i,format="{8}",size={9}i,ssim_index={10},cwnd={11}i,in_flight={12}i,min_rtt={13}i,rtt={14}i,delivery_rate={15}i,buffer={16},cum_rebuffer={17} {0}
    video_acked = pd.read_csv(f'{input_dir}video_acked.1.log', header=None)
    # video_acked,channel={1},server_id={2} expt_id={3}i,user="{4}",first_init_id={5}i,init_id={6}i,video_ts={7}i,ssim_index={8},buffer={9},cum_rebuffer={10} {0}
    buf = pd.read_csv(f'{input_dir}client_buffer.1.log', header=None)
    # client_buffer,channel={1},server_id={2} event="{3}",expt_id={4}i,user="{5}",first_init_id={6}i,init_id={7}i,buffer={8},cum_rebuf={9} {0}
    
    video_sent[15] = video_sent[15] * 8 / 1000000

    # Change the throughput to Mbps 
    video_sent[9] = video_sent[9] / 1000000

    # Converting the time first to datetime nad then to seconds
    buf[0] = pd.to_datetime(buf[0], unit='ms')
    video_sent[0] = pd.to_datetime(video_sent[0], unit='ms')
    video_acked[0] = pd.to_datetime(video_acked[0], unit='ms')


    video_start_time = video_sent[0].min()
    video_end_time = video_sent[0].max()
    # Bringing all of them back to the start time of the time the first video was
    buf[0] = buf[0] - video_start_time
    buf[0] = buf[0].dt.total_seconds()

    video_acked[0] = video_acked[0] - video_start_time
    video_acked[0] = video_acked[0].dt.total_seconds()

    video_sent[0] = video_sent[0] - video_start_time
    video_sent[0] = video_sent[0].dt.total_seconds()

    return video_sent, video_acked, buf, video_start_time, video_end_time

def draw_traces_throughput(bg, puffer , y_limits=None, custom_title=None):    
    # Draw background traffic throughput
    ax = setup_plot(y_limits) 
    custom_title = "" if custom_title is None else custom_title
    ax.plot(bg[1], bg[0], label='Background Traffic', color='tab:blue')
    ax.plot(puffer[1], puffer[0], label='Puffer Traffic', color='tab:red')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Throughput (Mbps)')
    ax.legend(loc='upper right')
    ax.set_title('Background traffic and puffer traffic throughput after shaping' + custom_title)
    caption = f'Background traffic: Average throughput = {bg[2]:.2f} Mbps, Burstiness = {bg[3]:.2f}\nPuffer traffic: Average throughput = {puffer[2]:.2f} Mbps, Burstiness = {puffer[3]:.2f}'
    plt.figtext(0.5, -0.12, caption, wrap=True, horizontalalignment='center', fontsize=16, bbox={'facecolor': 'white', 'alpha': 0.5, 'pad': 5})

    plt.show()
    
    
def draw_traces_epoch(throughputFile, epoch_len,  y_limits=None, x_limits=None,custom_title=None):    
    
    newTP = convert_to_epoch(throughputFile , epoch_len)
    # Instead of using time as x-axis, increament the x-axis by 1 for each data point
    ax = setup_plot(y_limits)
    custom_title = "" if custom_title is None else custom_title
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x)}'))
    if x_limits is not None:
        ax.set_xlim(x_limits)
    else:
        ax.set_xlim(0, len(newTP[0]))

    ax.plot(newTP [1], newTP [0], label='Traffic throughput per epoch', color='tab:blue')
    ax.set_xlabel('Epoch')
    ax.set_ylabel('Throughput (Mbps)')
    ax.set_title(f'Traffic throughput per epoch of {epoch_len} seconds, ' + custom_title )
    plt.show()
    
    
def draw_puffer_traces(puffer, y_limits=None, custom_title=None):
    # Draw puffer traffic throughput
    ax = setup_plot(y_limits) 
    custom_title = "" if custom_title is None else custom_title
    ax.plot(puffer[1], puffer[0], label='Puffer Traffic', color='tab:red')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Throughput (Mbps)')
    ax.set_title('Puffer traffic throughput after shaping '+ custom_title)
    caption = f'Puffer traffic: Average throughput = {puffer[2]:.2f} Mbps, Burstiness = {puffer[3]:.2f}'
    plt.figtext(0.5, -0.12, caption, wrap=True, horizontalalignment='center', fontsize=16, bbox={'facecolor': 'white', 'alpha': 0.5, 'pad': 5})
    plt.show()
    
def draw_bg_traces(bg , y_limits=None, custom_title=None):
    # Draw background traffic throughput
    ax = setup_plot(y_limits) 
    custom_title = "" if custom_title is None else custom_title
    ax.plot(bg[1], bg[0], label='Background Traffic', color='tab:blue')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Throughput (Mbps)')
    ax.set_title('Background traffic throughput ' + custom_title)
    caption = f'Background traffic: Average throughput = {bg[2]:.2f} Mbps, Burstiness = {bg[3]:.2f}'
    plt.figtext(0.5, -0.12, caption, wrap=True, horizontalalignment='center', fontsize=16, bbox={'facecolor': 'white', 'alpha': 0.5, 'pad': 5})
    plt.show()
    
def draw_buffer(buf, y_limits=None, custom_title=None):
    # Draw buffer occupancy
    ax = setup_plot(y_limits) 
    custom_title = "" if custom_title is None else custom_title
    ax.plot(buf[0], buf[8], label='Buffer Occupancy', color='tab:green')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Buffer Occupancy (s)')
    ax.set_title('Buffer occupancy ' + custom_title)
    plt.show()
    

def draw_video_chunk_size(video_sent, y_limits=None, custom_title=None):
    # Draw  video  chunk size  
    ax = setup_plot(y_limits)
    custom_title = "" if custom_title is None else custom_title
    ax.plot(video_sent[0], video_sent[9], label='Chunk size in Mega bytes', color='blue')
    ax.set_title('Video chunk size during watching video '+ custom_title)
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Chunk size (Mega bytes)', )
    plt.show()
    
def draw_ssim(video_sent, y_limits=None, custom_title=None):
    # Draw  video  chunk size  
    ax = setup_plot(y_limits)
    custom_title = "" if custom_title is None else custom_title
    ax.plot(video_sent[0], video_sent[10], label='SSIM index', color='red')
    ax.set_title('SSIM index during watching video '+ custom_title)
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('SSIM index', )
    plt.show()
    
def draw_delivery_rate(video_sent, y_limits=None, custom_title=None):
    # Draw  video  chunk size  
    ax = setup_plot(y_limits)
    custom_title = "" if custom_title is None else custom_title
    ax.plot(video_sent[0], video_sent[15], label='Delivery rate in Mbps', color='purple')
    ax.set_title('Delivery rate during watching video '+ custom_title)
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Delivery rate (Mbps)', )
    caption = f'Average delivery rate = {video_sent[15].mean():.2f} Mbps'
    plt.figtext(0.5, -0.12, caption, wrap=True, horizontalalignment='center', fontsize=16, bbox={'facecolor': 'white', 'alpha': 0.5, 'pad': 5})
    plt.show()

def draw_video_bitrate(video_sent, y_limits=None, custom_title=None):
    # Draw  video  chunk size  
    category_order = ['640x360-24', '854x480-26', '854x480-24', '1280x720-26', '1280x720-24', '1280x720-22', '1280x720-20', '1920x1080-24', '1920x1080-22']

    video_format_indices = [category_order.index(fmt) for fmt in video_sent[8]]

    ax = setup_plot(y_limits)
    custom_title = "" if custom_title is None else custom_title
    ax.plot(video_sent[0], video_format_indices, label='Video Format', color='green')
    ax.set_title('Video format changes during watching video ' + custom_title)
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Video Format', )

    ax.set_yticks(range(len(category_order)))
    ax.set_yticklabels(category_order)
    plt.yticks(rotation=45)
    plt.show()
    
    
def convert_to_epoch(inputTraffic, epoch_len):
    time = np.array(inputTraffic[1])
    throughput = np.array(inputTraffic[0])

    num_intervals = int(np.ceil(time[-1] / epoch_len))
    time_6s = []
    throughput_6s = []
    for i in range(num_intervals):
        start_time = i * epoch_len
        end_time = (i + 1) * epoch_len
        mask = (time >= start_time) & (time < end_time)
        interval_throughput = throughput[mask]
        avg_throughput = np.mean(interval_throughput) if len(interval_throughput) > 0 else 0

        time_6s.append(start_time + epoch_len / 2)  # Use the middle of the interval for the timestamp
        throughput_6s.append(avg_throughput)
    return  throughput_6s ,time_6s
    

    
def mergeSentAckedSize(video_sent, video_acked):
    # video_acked,channel={1},server_id={2} expt_id={3}i,user="{4}",first_init_id={5}i,init_id={6}i,video_ts={7}i,ssim_index={8},buffer={9},cum_rebuffer={10} {0}
    # video_sent,channel={1},server_id={2} expt_id={3}i,user="{4}",first_init_id={5}i,init_id={6}i,video_ts={7}i,format="{8}",size={9}i,ssim_index={10},cwnd={11}i,in_flight={12}i,min_rtt={13}i,rtt={14}i,delivery_rate={15}i,buffer={16},cum_rebuffer={17} {0}
    # video_size = pd.read_csv("/home/jaber/pufferData/video_size.csv")
    cnt = 0
    totalMismatch = 0
    combined = []
    for sentEntry in video_sent.values:
        ackedEntry = video_acked.loc[(video_acked[7] == sentEntry[7])]

        if ackedEntry.empty:
            totalMismatch += 1
            continue
        ackedEntryTime = ackedEntry[0]
        sentTime = sentEntry[0]
        videoSize = sentEntry[9]
        # print(f'Video size is {videoSize}')
        # print(f'Acked time is {ackedEntryTime}')
        # print(f'time is {sentTime}')
        # print(f'{ackedEntryTime - sentTime} duration')
        duration = ackedEntryTime - sentTime
        throughput_per_chunk = videoSize / duration
        combined.append([sentEntry[5] , sentTime, ackedEntryTime, videoSize, duration, throughput_per_chunk])

        # Save the combined data into a dataframe
        combined_df = pd.DataFrame(combined, columns=['video_ts', 'sent_time', 'acked_time', 'video_size', 'duration', 'throughput_per_chunk'])
        combined_df.to_csv('/home/laasya/cs190n-fall-2024/discussions/week5/results/combined.csv', index=False)
    print(totalMismatch) 
    return combined_df

def draw_sent_acked(video_sent, video_acked, y_limits=None, custom_title=None):
    combined_df = mergeSentAckedSize(video_sent, video_acked)
    combined_df['throughput_per_chunk'] = combined_df['throughput_per_chunk'].astype(str).str.extract(r'(\d+\.\d+)').astype(float)
    # Calculate the average of throughput_per_chunk
    average_throughput = combined_df['throughput_per_chunk'].mean()
    ax = setup_plot(y_limits)
    ax.plot(combined_df['sent_time'], combined_df['throughput_per_chunk'], label='Delivery rate in Mbps', color='purple', linestyle='--')
    custom_title = "" if custom_title is None else custom_title

    ax.set_title('Throughput per chunk (Ack time - Sent time) / Size, ' +  custom_title ) 
    ax.set_xlabel('Time (s)')
    caption = 'Average throughput: {:.2f} Mbps'.format(average_throughput)
    plt.figtext(0.5, -0.12, caption, wrap=True, horizontalalignment='center', fontsize=16, bbox={'facecolor': 'white', 'alpha': 0.5, 'pad': 5})
    plt.show()