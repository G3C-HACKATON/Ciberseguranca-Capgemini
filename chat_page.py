import streamlit as st
import os
import sys
import time
from datetime import datetime

# Adicionar diretório atual ao path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Importar componentes necessários
from config import Config
from logger import SecurityLogger
from security_agent import SecurityAgent
from threat_intelligence import ThreatIntelligence
from notification import NotificationSystem
from chat import run_streamlit_mode

def chat_page():
    """Página do chat de segurança cibernética."""
    st.set_page_config(
        page_title="CyberBot: Assistente de Segurança",
        page_icon="💬",
        layout="wide"
    )

    # Inicializar componentes
    try:
        config = Config()
        logger = SecurityLogger()
        threat_intel = ThreatIntelligence(config)
        notification_system = NotificationSystem(config)
        security_agent = SecurityAgent(config, logger, threat_intel, notification_system)
        
        # Configuração de estado da sessão para o agente
        if 'agent_initialized' not in st.session_state:
            logger.log_activity("CyberBot inicializado com sucesso", 'success')
            st.session_state.agent_initialized = True
            
        # Empacotar componentes
        security_components = {
            "config": config,
            "logger": logger,
            "threat_intel": threat_intel,
            "security_agent": security_agent,
            "notification": notification_system
        }
        
        # Executar o chat com integração com o agente de segurança
        run_streamlit_mode(security_components)
        
    except Exception as e:
        st.error(f"Erro ao inicializar o CyberBot: {str(e)}")
        import traceback
        st.error(traceback.format_exc())

if __name__ == "__main__":
    chat_page() 