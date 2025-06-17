import time
import re
import json
import logging
import threading
import PyPDF2
import dns.resolver
import dns.exception
import customtkinter as ctk
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tkinter import messagebox, filedialog
from PIL import Image
import base64
import pytesseract
from pdf2image import convert_from_path
import io
import os
import pdfplumber
from pdfminer.high_level import extract_text as pdfminer_extract_text

# Configuração do tema
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Configure Tesseract path (update this according to your system)
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

class LogHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state="normal")
            self.text_widget.insert("end", msg + "\n")
            self.text_widget.configure(state="disabled")
            self.text_widget.see("end")
        self.text_widget.after(0, append)

class PDFHandler(FileSystemEventHandler):
    def __init__(self, api_key, email, monitor_folder, sent_folder, error_folder, 
                 email_template, error_template, update_stats_callback, logger):
        self.api_key = api_key
        self.email = email
        self.monitor_folder = monitor_folder
        self.sent_folder = sent_folder
        self.error_folder = error_folder
        self.email_template = email_template
        self.error_template = error_template
        self.update_stats = update_stats_callback
        self.logger = logger
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        self.processed_files = 0
        self.emails_sent = 0
        self.errors = 0

    def validate_email(self, email):
        """Valida um endereço de email com verificação DNS MX"""
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False
            
        domain = email.split('@')[-1]
        try:
            try:
                mx_records = self.resolver.resolve(domain, 'MX')
                if len(mx_records) == 0:
                    self.logger.warning(f"Domínio {domain} não possui registros MX válidos")
                    return False
                return True
            except dns.resolver.NoAnswer:
                self.logger.warning(f"Domínio {domain} não possui registros MX")
                return False
            except dns.resolver.NXDOMAIN:
                self.logger.warning(f"Domínio {domain} não existe")
                return False
            except dns.resolver.Timeout:
                self.logger.warning(f"Timeout ao verificar MX para {domain}")
                return False
            except dns.exception.DNSException as e:
                self.logger.warning(f"Erro DNS ao verificar {domain}: {str(e)}")
                return False
        except Exception as e:
            self.logger.error(f"Erro inesperado ao validar email {email}: {str(e)}")
            return False

    def preprocess_image(self, image):
        """Pré-processa a imagem para melhorar o OCR"""
        # Convert to grayscale
        img = image.convert('L')
        
        # Apply thresholding
        img = img.point(lambda x: 0 if x < 140 else 255)
        
        return img

    def extract_text_from_image(self, image):
        """Extrai texto de imagem usando OCR com pré-processamento"""
        try:
            processed_img = self.preprocess_image(image)
            custom_config = r'--oem 3 --psm 6 -l por+eng'
            text = pytesseract.image_to_string(processed_img, config=custom_config)
            return text
        except Exception as e:
            self.logger.error(f"Erro no OCR: {str(e)}")
            return ""

    def extract_emails_from_pdf(self, pdf_path, use_ocr=False): 
        """Extrai emails de PDF usando múltiplos métodos"""
        try:
            text = ""
            
            if use_ocr:
                # Converter PDF para imagens e processar cada uma com OCR
                images = convert_from_path(pdf_path)
                for img in images:
                    text += self.extract_text_from_image(img) + "\n"
            else:
                # Tentar diferentes métodos de extração de texto
                for library in ["pdfplumber", "pypdf2", "pdfminer"]:
                    try:
                        if library == "pypdf2":
                            with open(pdf_path, 'rb') as file:
                                reader = PyPDF2.PdfReader(file)
                            for page in reader.pages:
                                extracted = page.extract_text() or ""
                                text += extracted
                            break
                                
                        elif library == "pdfminer":
                            text = pdfminer_extract_text(pdf_path)
                            break
                            
                        elif library == "pdfplumber":
                            with pdfplumber.open(pdf_path) as pdf:
                                for page in pdf.pages:
                                    extracted = page.extract_text() or ""
                                    text += extracted
                            break
                            
                    except Exception as e:
                        self.logger.debug(f"Falha com {library}: {str(e)}")
                        continue
            
            # Padrão regex melhorado para emails
            email_pattern = r"""
                [a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+  # parte local
                @                                  # símbolo @
                [a-zA-Z0-9-]+                      # domínio
                (?:\.[a-zA-Z0-9-]+)*               # subdomínios
                \.[a-zA-Z]{2,}                     # TLD
            """
            
            potential_emails = re.findall(email_pattern, text, re.VERBOSE)
            valid_emails = []
            seen_emails = set()
            
            for email in potential_emails:
                email = email.strip().lower()
                if (email not in seen_emails and 
                    self.validate_email(email)):
                    valid_emails.append(email)
                    seen_emails.add(email)
            
            if not valid_emails:
                self.logger.debug(f"Nenhum e-mail válido encontrado. Texto extraído: {text[:500]}...")
                # Fallback para OCR se nenhum email for encontrado no texto
                if not use_ocr:
                    self.logger.debug("Tentando OCR como fallback...")
                    return self.extract_emails_from_pdf(pdf_path, use_ocr=True)
            
            return valid_emails
            
        except Exception as e:
            self.logger.error(f"Erro ao extrair e-mails do PDF {pdf_path}: {str(e)}")
            return []

    def create_email_message(self, recipient, pdf_path, error=None):
        """Cria a mensagem de email com ou sem anexo"""
        filename = os.path.basename(pdf_path)
        
        if error:
            subject = f"Erro no processamento do arquivo: {filename}"
            body = self.error_template.format(nome_arquivo=filename, erro=error)
        else:
            subject = f"Envio automático do arquivo: {filename}"
            body = self.email_template.format(nome_arquivo=filename)
        
        message = Mail(
            from_email=self.email,
            to_emails=recipient,
            subject=subject,
            plain_text_content=body
        )
        
        if not error:
            with open(pdf_path, 'rb') as f:
                data = f.read()
                encoded = base64.b64encode(data).decode()
                
            attachment = Attachment(
                FileContent(encoded),
                FileName(filename),
                FileType('application/pdf'),
                Disposition('attachment')
            )
            message.attachment = attachment
            
        return message

    def send_email(self, recipient, pdf_path, error=None):
        """Envia o email usando a API SendGrid"""
        try:
            message = self.create_email_message(recipient, pdf_path, error)
            sg = SendGridAPIClient(self.api_key)
            response = sg.send(message)
            
            if response.status_code in [200, 202]:
                self.logger.info(f"Email enviado com sucesso para: {recipient}")
                return True
            else:
                self.logger.error(f"Falha ao enviar email para {recipient}. Status code: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Erro ao enviar email para {recipient}: {str(e)}")
            return False

    def move_file(self, source, destination_folder):
        """Move o arquivo para a pasta de destino"""
        try:
            if not os.path.exists(destination_folder):
                os.makedirs(destination_folder)
            destination = os.path.join(destination_folder, os.path.basename(source))
            
            # Verifica se o arquivo de destino já existe
            counter = 1
            base, ext = os.path.splitext(destination)
            while os.path.exists(destination):
                destination = f"{base}_{counter}{ext}"
                counter += 1
                
            os.rename(source, destination)
            return destination
        except Exception as e:
            self.logger.error(f"Erro ao mover arquivo {source}: {str(e)}")
            return None

    def on_created(self, event):
        """Lida com novos arquivos detectados"""
        if not event.is_directory and event.src_path.lower().endswith('.pdf'):
            self.logger.info(f"Novo arquivo PDF detectado: {event.src_path}")
            time.sleep(2)  # Espera o arquivo ser completamente escrito
            self.process_pdf(event.src_path)

    def process_pdf(self, pdf_path):
        """Processa um arquivo PDF individual"""
        try:
            emails = self.extract_emails_from_pdf(pdf_path, use_ocr=False)
            processed = 1
            sent = 0
            errors = 0
            
            if emails:
                success = True
                for email in emails:
                    if self.send_email(email, pdf_path):
                        sent += 1
                    else:
                        success = False
                        errors += 1
                
                if success:
                    self.move_file(pdf_path, self.sent_folder)
                    self.logger.info(f"Arquivo {pdf_path} processado com sucesso e movido para enviados")
                else:
                    self.move_file(pdf_path, self.error_folder)
                    self.logger.warning(f"Arquivo {pdf_path} movido para erros devido a falhas no envio")
                    errors += 1
            else:
                error_msg = "Nenhum email válido encontrado no documento"
                self.logger.warning(error_msg)
                self.send_email(self.email, pdf_path, error=error_msg)
                self.move_file(pdf_path, self.error_folder)
                errors += 1
                
            self.update_stats(processed, sent, errors)
        except Exception as e:
            self.logger.error(f"Erro ao processar arquivo {pdf_path}: {str(e)}")
            self.update_stats(1, 0, 1)
            self.move_file(pdf_path, self.error_folder)

class EmailAutomationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Automação de Envio de Emails")
        self.root.geometry("1000x800")
        
        # Variáveis de controle
        self.monitoring = False
        self.observer = None
        self.handler = None
        
        # Configuração do layout
        self.setup_ui()
        
        # Configuração do logging
        self.setup_logging()
        
        # Carregar configurações salvas
        self.load_settings()
        
        # Configurar evento de fechamento
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        """Configura a interface do usuário"""
        # Frame principal
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Notebook (abas)
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Abas
        self.tabview.add("Configuração")
        self.tabview.add("Monitoramento")
        self.tabview.add("Logs")
        
        # Configuração da aba de Configuração
        self.setup_config_tab()
        
        # Configuração da aba de Monitoramento
        self.setup_monitor_tab()
        
        # Configuração da aba de Logs
        self.setup_logs_tab()
    
    def setup_config_tab(self):
        """Configura a aba de configuração"""
        tab = self.tabview.tab("Configuração")
        
        # Frame de rolagem
        scroll_frame = ctk.CTkScrollableFrame(tab)
        scroll_frame.pack(fill="both", expand=True)
        
        # Seção de configuração do SendGrid
        ctk.CTkLabel(scroll_frame, text="Configuração do SendGrid", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 10))
        
        ctk.CTkLabel(scroll_frame, text="API Key:").pack(anchor="w")
        self.api_key_entry = ctk.CTkEntry(scroll_frame, width=400, show="*")
        self.api_key_entry.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(scroll_frame, text="Email de Remetente:").pack(anchor="w")
        self.sender_email_entry = ctk.CTkEntry(scroll_frame, width=400)
        self.sender_email_entry.pack(fill="x", pady=(0, 20))
        
        # Seção de pastas
        ctk.CTkLabel(scroll_frame, text="Configuração de Pastas", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Monitorar pasta
        folder_frame = ctk.CTkFrame(scroll_frame)
        folder_frame.pack(fill="x", pady=(0, 5))
        
        ctk.CTkLabel(folder_frame, text="Pasta para Monitorar:").pack(side="left", padx=(0, 10))
        self.monitor_folder_entry = ctk.CTkEntry(folder_frame)
        self.monitor_folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(folder_frame, text="Selecionar", width=100, 
                     command=lambda: self.select_folder(self.monitor_folder_entry)).pack(side="left")
        
        # Pasta de enviados
        folder_frame = ctk.CTkFrame(scroll_frame)
        folder_frame.pack(fill="x", pady=(0, 5))
        
        ctk.CTkLabel(folder_frame, text="Pasta de Enviados:").pack(side="left", padx=(0, 10))
        self.sent_folder_entry = ctk.CTkEntry(folder_frame)
        self.sent_folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(folder_frame, text="Selecionar", width=100, 
                     command=lambda: self.select_folder(self.sent_folder_entry)).pack(side="left")
        
        # Pasta de erros
        folder_frame = ctk.CTkFrame(scroll_frame)
        folder_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(folder_frame, text="Pasta de Erros:").pack(side="left", padx=(0, 10))
        self.error_folder_entry = ctk.CTkEntry(folder_frame)
        self.error_folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(folder_frame, text="Selecionar", width=100, 
                     command=lambda: self.select_folder(self.error_folder_entry)).pack(side="left")
        
        # Templates de email
        ctk.CTkLabel(scroll_frame, text="Templates de Email", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 10))
        
        ctk.CTkLabel(scroll_frame, text="Template Normal:").pack(anchor="w")
        self.email_template_text = ctk.CTkTextbox(scroll_frame, height=100)
        self.email_template_text.pack(fill="x", pady=(0, 10))
        self.email_template_text.insert("1.0", "Prezado,\n\nSegue em anexo o documento {nome_arquivo}.\n\nAtenciosamente,\nEquipe de Automação")
        
        ctk.CTkLabel(scroll_frame, text="Template de Erro:").pack(anchor="w")
        self.error_template_text = ctk.CTkTextbox(scroll_frame, height=100)
        self.error_template_text.pack(fill="x", pady=(0, 20))
        self.error_template_text.insert("1.0", "Prezado,\n\nOcorreu um erro ao processar o arquivo {nome_arquivo}:\n\n{erro}\n\nAtenciosamente,\nEquipe de Automação")
        
        # Botões de ação
        button_frame = ctk.CTkFrame(scroll_frame)
        button_frame.pack(fill="x", pady=(10, 0))
        
        self.save_button = ctk.CTkButton(button_frame, text="Salvar Configurações", command=self.save_settings)
        self.save_button.pack(side="right", padx=5)
        
        self.load_button = ctk.CTkButton(button_frame, text="Carregar Configurações", command=self.load_settings)
        self.load_button.pack(side="right", padx=5)
    
    def setup_monitor_tab(self):
        """Configura a aba de monitoramento"""
        tab = self.tabview.tab("Monitoramento")
        
        # Frame principal
        main_frame = ctk.CTkFrame(tab)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Botões de controle
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(fill="x", pady=(0, 20))
        
        self.start_button = ctk.CTkButton(button_frame, text="Iniciar Monitoramento", command=self.start_monitoring)
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ctk.CTkButton(button_frame, text="Parar Monitoramento", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="left", padx=5)
        
        self.process_button = ctk.CTkButton(button_frame, text="Processar Pasta", command=self.process_folder)
        self.process_button.pack(side="left", padx=5)
        
        # Estatísticas
        stats_frame = ctk.CTkFrame(main_frame)
        stats_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(stats_frame, text="Estatísticas", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 10))
        
        stats_grid = ctk.CTkFrame(stats_frame)
        stats_grid.pack(fill="x")
        
        ctk.CTkLabel(stats_grid, text="Arquivos Processados:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.processed_label = ctk.CTkLabel(stats_grid, text="0", font=("Arial", 12, "bold"))
        self.processed_label.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        ctk.CTkLabel(stats_grid, text="Emails Enviados:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.sent_label = ctk.CTkLabel(stats_grid, text="0", font=("Arial", 12, "bold"))
        self.sent_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        
        ctk.CTkLabel(stats_grid, text="Erros:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.errors_label = ctk.CTkLabel(stats_grid, text="0", font=("Arial", 12, "bold"))
        self.errors_label.grid(row=2, column=1, sticky="w", padx=5, pady=5)
        
        # Status do monitoramento
        self.status_label = ctk.CTkLabel(main_frame, text="Status: Inativo", text_color="gray")
        self.status_label.pack(anchor="w", pady=(10, 0))
    
    def setup_logs_tab(self):
        """Configura a aba de logs"""
        tab = self.tabview.tab("Logs")
        
        # Frame principal
        main_frame = ctk.CTkFrame(tab)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Controles de log
        control_frame = ctk.CTkFrame(main_frame)
        control_frame.pack(fill="x", pady=(0, 5))
        
        self.clear_logs_button = ctk.CTkButton(control_frame, text="Limpar Logs", command=self.clear_logs)
        self.clear_logs_button.pack(side="left", padx=5)
        
        self.save_logs_button = ctk.CTkButton(control_frame, text="Salvar Logs", command=self.save_logs)
        self.save_logs_button.pack(side="left", padx=5)
        
        # Área de logs
        self.log_text = ctk.CTkTextbox(main_frame, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True)
    
    def setup_logging(self):
        """Configura o sistema de logging"""
        self.logger = logging.getLogger("EmailAutomation")
        self.logger.setLevel(logging.INFO)
        
        # Remove handlers existentes
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Adiciona handler personalizado
        log_handler = LogHandler(self.log_text)
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(log_handler)
    
    def select_folder(self, entry_widget):
        """Abre diálogo para selecionar pasta"""
        folder = filedialog.askdirectory()
        if folder:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, folder)
    
    def update_stats(self, processed=0, sent=0, errors=0):
        """Atualiza as estatísticas na interface"""
        current_processed = int(self.processed_label.cget("text"))
        current_sent = int(self.sent_label.cget("text"))
        current_errors = int(self.errors_label.cget("text"))
        
        self.processed_label.configure(text=str(current_processed + processed))
        self.sent_label.configure(text=str(current_sent + sent))
        self.errors_label.configure(text=str(current_errors + errors))
        
        # Atualiza imediatamente a interface
        self.root.update()
    
    def update_status(self, monitoring):
        """Atualiza o status do monitoramento"""
        if monitoring:
            self.status_label.configure(text="Status: Ativo", text_color="green")
        else:
            self.status_label.configure(text="Status: Inativo", text_color="gray")
    
    def validate_fields(self):
        """Valida os campos obrigatórios"""
        required_fields = [
            (self.api_key_entry, "API Key do SendGrid é obrigatória"),
            (self.sender_email_entry, "Email de remetente é obrigatório"),
            (self.monitor_folder_entry, "Pasta para monitorar é obrigatória"),
            (self.sent_folder_entry, "Pasta de enviados é obrigatória"),
            (self.error_folder_entry, "Pasta de erros é obrigatória")
        ]
        
        for field, error_msg in required_fields:
            if not field.get().strip():
                messagebox.showerror("Erro de Validação", error_msg)
                field.focus_set()
                return False
        
        return True
    
    def start_monitoring(self):
        """Inicia o monitoramento da pasta"""
        if not self.validate_fields():
            return
        
        if self.monitoring:
            messagebox.showwarning("Aviso", "O monitoramento já está em andamento")
            return
        
        try:
            self.handler = PDFHandler(
                api_key=self.api_key_entry.get(),
                email=self.sender_email_entry.get(),
                monitor_folder=self.monitor_folder_entry.get(),
                sent_folder=self.sent_folder_entry.get(),
                error_folder=self.error_folder_entry.get(),
                email_template=self.email_template_text.get("1.0", "end").strip(),
                error_template=self.error_template_text.get("1.0", "end").strip(),
                update_stats_callback=self.update_stats,
                logger=self.logger
            )
            
            self.observer = Observer()
            self.observer.schedule(self.handler, self.monitor_folder_entry.get(), recursive=False)
            self.observer.start()
            
            self.monitoring = True
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.update_status(True)
            
            self.logger.info(f"Iniciado monitoramento da pasta: {self.monitor_folder_entry.get()}")
        except Exception as e:
            self.logger.error(f"Erro ao iniciar monitoramento: {str(e)}")
            messagebox.showerror("Erro", f"Falha ao iniciar monitoramento: {str(e)}")
    
    def stop_monitoring(self):
        """Para o monitoramento da pasta"""
        if not self.monitoring:
            return
        
        try:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.update_status(False)
            self.logger.info("Monitoramento parado com sucesso")
        except Exception as e:
            self.logger.error(f"Erro ao parar monitoramento: {str(e)}")
            messagebox.showerror("Erro", f"Falha ao parar monitoramento: {str(e)}")
    
    def process_folder(self):
        """Processa todos os PDFs na pasta de monitoramento"""
        if not self.validate_fields():
            return
        
        monitor_folder = self.monitor_folder_entry.get()
        if not os.path.exists(monitor_folder):
            messagebox.showerror("Erro", f"A pasta {monitor_folder} não existe")
            return
        
        try:
            self.logger.info(f"Iniciando processamento em lote da pasta: {monitor_folder}")
            
            # Criar handler temporário para processamento
            handler = PDFHandler(
                api_key=self.api_key_entry.get(),
                email=self.sender_email_entry.get(),
                monitor_folder=monitor_folder,
                sent_folder=self.sent_folder_entry.get(),
                error_folder=self.error_folder_entry.get(),
                email_template=self.email_template_text.get("1.0", "end").strip(),
                error_template=self.error_template_text.get("1.0", "end").strip(),
                update_stats_callback=self.update_stats,
                logger=self.logger
            )
            
            # Processar todos os PDFs na pasta
            pdf_files = [f for f in os.listdir(monitor_folder) if f.lower().endswith('.pdf')]
            total = len(pdf_files)
            
            if total == 0:
                self.logger.info("Nenhum arquivo PDF encontrado para processar")
                return
            
            self.logger.info(f"Encontrados {total} arquivos PDF para processar")
            
            progress_window = ctk.CTkToplevel(self.root)
            progress_window.title("Processando...")
            progress_window.geometry("400x100")
            progress_window.grab_set()
            
            progress_label = ctk.CTkLabel(progress_window, text=f"Processando 0 de {total} arquivos...")
            progress_label.pack(pady=10)
            
            progress_bar = ctk.CTkProgressBar(progress_window)
            progress_bar.pack(fill="x", padx=20, pady=5)
            progress_bar.set(0)
            
            def process_files():
                for i, filename in enumerate(pdf_files, 1):
                    filepath = os.path.join(monitor_folder, filename)
                    self.logger.info(f"Processando arquivo {i}/{total}: {filename}")
                    handler.process_pdf(filepath)
                    
                    # Atualizar progresso
                    progress = i / total
                    progress_bar.set(progress)
                    progress_label.configure(text=f"Processando {i} de {total} arquivos...")
                    progress_window.update()
                
                progress_window.destroy()
                self.logger.info("Processamento em lote concluído")
                messagebox.showinfo("Concluído", f"Processados {total} arquivos PDF")
            
            # Executar em uma thread separada para não travar a interface
            threading.Thread(target=process_files, daemon=True).start()
            
        except Exception as e:
            self.logger.error(f"Erro durante o processamento em lote: {str(e)}")
            messagebox.showerror("Erro", f"Falha no processamento: {str(e)}")
    
    def save_settings(self):
        """Salva as configurações em um arquivo"""
        settings = {
            'api_key': self.api_key_entry.get(),
            'sender_email': self.sender_email_entry.get(),
            'monitor_folder': self.monitor_folder_entry.get(),
            'sent_folder': self.sent_folder_entry.get(),
            'error_folder': self.error_folder_entry.get(),
            'email_template': self.email_template_text.get("1.0", "end").strip(),
            'error_template': self.error_template_text.get("1.0", "end").strip()
        }
        
        try:
            with open('email_automation_settings.json', 'w') as f:
                json.dump(settings, f, indent=4)
            self.logger.info("Configurações salvas com sucesso")
            messagebox.showinfo("Sucesso", "Configurações salvas com sucesso")
        except Exception as e:
            self.logger.error(f"Erro ao salvar configurações: {str(e)}")
            messagebox.showerror("Erro", f"Falha ao salvar configurações: {str(e)}")
    
    def load_settings(self):
        """Carrega as configurações salvas"""
        try:
            if os.path.exists('email_automation_settings.json'):
                with open('email_automation_settings.json', 'r') as f:
                    settings = json.load(f)
                
                self.api_key_entry.delete(0, "end")
                self.api_key_entry.insert(0, settings.get('api_key', ''))
                
                self.sender_email_entry.delete(0, "end")
                self.sender_email_entry.insert(0, settings.get('sender_email', ''))
                
                self.monitor_folder_entry.delete(0, "end")
                self.monitor_folder_entry.insert(0, settings.get('monitor_folder', ''))
                
                self.sent_folder_entry.delete(0, "end")
                self.sent_folder_entry.insert(0, settings.get('sent_folder', ''))
                
                self.error_folder_entry.delete(0, "end")
                self.error_folder_entry.insert(0, settings.get('error_folder', ''))
                
                self.email_template_text.delete("1.0", "end")
                self.email_template_text.insert("1.0", settings.get('email_template', ''))
                
                self.error_template_text.delete("1.0", "end")
                self.error_template_text.insert("1.0", settings.get('error_template', ''))
                
                self.logger.info("Configurações carregadas com sucesso")
        except Exception as e:
            self.logger.error(f"Erro ao carregar configurações: {str(e)}")
    
    def clear_logs(self):
        """Limpa os logs da interface"""
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.logger.info("Logs limpos")
    
    def save_logs(self):
        """Salva os logs em um arquivo"""
        try:
            logs = self.log_text.get("1.0", "end")
            if not logs.strip():
                messagebox.showwarning("Aviso", "Nenhum log para salvar")
                return
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("Arquivos de Log", "*.log"), ("Arquivos de Texto", "*.txt")],
                title="Salvar Logs"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(logs)
                self.logger.info(f"Logs salvos em: {file_path}")
                messagebox.showinfo("Sucesso", "Logs salvos com sucesso")
        except Exception as e:
            self.logger.error(f"Erro ao salvar logs: {str(e)}")
            messagebox.showerror("Erro", f"Falha ao salvar logs: {str(e)}")
    
    def on_closing(self):
        """Lida com o fechamento da janela"""
        if self.monitoring:
            self.stop_monitoring()
        self.root.destroy()

if __name__ == "__main__":
    root = ctk.CTk()
    app = EmailAutomationApp(root)
    root.mainloop()
