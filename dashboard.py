import streamlit as st
import pandas as pd 
import plotly.express as px
import plotly.graph_objects as go 
from scapy.all import *
from collections import defaultdict
import time 
from datetime import datetime 
import threading
import warnings
import logging
from typing import  Dict,List,  Optional
import socket
import math


logging.basicConfig(
    level=logging.INFO,
    format = '%(asctime)s - %(levelname)s - %(messages)s'
)
logger = logging.getLogger(__name__)


class PacketProcessor:
    
    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
            
         }
        self.packet_data =[]
        self.start_time = datetime.now()
        self.packet_count=0 
        self.lock = threading.lock()
    
    def get_protocol_name(self,protocol_num: int) -> int :
        "Convert protocol number to name"
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')
    
    def process_packet(self,packet) -> None:
        """Process a single packet and extract relevant information"""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp' : datetime.now(),
                        'source': packet[IP].src,
                        'destiantion': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }
            if TCP in packet:
                packet_info.update({
                    'src_port':  packet[TCP].sport,
                    'dst_port':  packet[TCP].dport,
                    'tcp_flags': packet[TCP].flags       
                }) 
            elif UDP in packet:
                packet_info.update({
                    'src_port':  packet[TCP].sport,
                    'dst_port':  packet[TCP].dport,   
                }) 
            self.packet_data.append(packet_info)
            self.packet_count +=1
            
            
            if len(self.packet_data) > 10000:
                self.packet_data.pop(0)
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
    
    
    def get_dataframe(self) -> pd.DataFrame:
        with self.lock:
            return pd.DataFrame(self.packet_data)   
        
    
def start_packet_capture():
    processor = PacketProcessor()
        
    def capture_packets():
        sniff(prn=processor.process_packet, store=False)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    return processor
    



def  create_visualizations(df: pd.DataFrame):
        
    if len(df) > 0 :
            
            protocol_counts = df['protocol'].value_counts()
            fig_protocol =px.pie(
                values=protocol_counts.values,
                names=protocol_counts.index,
                title="Protocol Distribution"
            )       
            
            st.plotly_chart(fig_protocol,use_container_width=True)
            
            
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
            fig_timeline = px.line(
                x=df_grouped.index,
                y=df_grouped.values,
                title = "Packets per Second"
                
            )   
            
            st.plotly_chart(fig_timeline,use_container_width=True)
            
            top_sources = df['sources'].value_counts().head(10)
            fig_sources =  px.bar(
                x=top_sources.index,
                y=top_sources.values,
                title= "Top Source IP Addresses"
                
            )                                
            
            st.plotly_chart(fig_sources,use_container_width=True)









def main():
    """Main function to run the dashboard"""
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # Initialize packet processor in session state
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    # Create dashboard layout
    col1, col2 = st.columns(2)

    # Get current data
    df = st.session_state.processor.get_dataframe()

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )

    # Add refresh button
    if st.button('Refresh Data'):
        st.rerun()

    # Auto refresh
    time.sleep(2)
    st.rerun()

        