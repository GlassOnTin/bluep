"""Structured logging utilities for better observability."""

import json
import logging
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
import functools

# Context variables for request-scoped data
trace_id_var: ContextVar[Optional[str]] = ContextVar('trace_id', default=None)
session_id_var: ContextVar[Optional[str]] = ContextVar('session_id', default=None)
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs JSON structured logs."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Base log data
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add context variables if set
        if trace_id := trace_id_var.get():
            log_data['trace_id'] = trace_id
        if session_id := session_id_var.get():
            log_data['session_id'] = session_id
        if request_id := request_id_var.get():
            log_data['request_id'] = request_id
        
        # Add any extra fields from the record
        if hasattr(record, 'extra') and isinstance(record.extra, dict):
            if 'extra_fields' in record.extra:
                log_data.update(record.extra['extra_fields'])
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


class StructuredLogger:
    """Logger wrapper that adds structured logging capabilities."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._setup_structured_handler()
    
    def isEnabledFor(self, level: int) -> bool:
        """Check if logger is enabled for a given level."""
        return self.logger.isEnabledFor(level)
    
    def _setup_structured_handler(self):
        """Replace existing handlers with structured formatter."""
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Add new handler with structured formatter
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredFormatter())
        self.logger.addHandler(handler)
    
    def _log_with_context(self, level: int, msg: str, *args, 
                         extra_fields: Optional[Dict[str, Any]] = None, **kwargs):
        """Log with additional context fields."""
        extra = kwargs.get('extra', {})
        
        # Add performance metrics
        extra['performance'] = {
            'timestamp_ms': int(time.time() * 1000)
        }
        
        # Add extra fields if provided
        if extra_fields:
            extra['extra_fields'] = extra_fields
        
        kwargs['extra'] = extra
        self.logger.log(level, msg, *args, **kwargs)
    
    def debug(self, msg: str, *args, **kwargs):
        """Log debug message with context."""
        self._log_with_context(logging.DEBUG, msg, *args, **kwargs)
    
    def info(self, msg: str, *args, **kwargs):
        """Log info message with context."""
        self._log_with_context(logging.INFO, msg, *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs):
        """Log warning message with context."""
        self._log_with_context(logging.WARNING, msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs):
        """Log error message with context."""
        self._log_with_context(logging.ERROR, msg, *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs):
        """Log critical message with context."""
        self._log_with_context(logging.CRITICAL, msg, *args, **kwargs)


def get_structured_logger(name: str) -> StructuredLogger:
    """Get or create a structured logger."""
    logger = logging.getLogger(name)
    return StructuredLogger(logger)


def set_trace_context(trace_id: Optional[str] = None, 
                     session_id: Optional[str] = None,
                     request_id: Optional[str] = None):
    """Set context variables for structured logging."""
    if trace_id:
        trace_id_var.set(trace_id)
    if session_id:
        session_id_var.set(session_id)
    if request_id:
        request_id_var.set(request_id)


def generate_trace_id() -> str:
    """Generate a unique trace ID."""
    return str(uuid.uuid4())


def generate_request_id() -> str:
    """Generate a unique request ID."""
    return f"req_{uuid.uuid4().hex[:12]}"


def with_trace_context(func):
    """Decorator to automatically set trace context for async functions."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Generate request ID if not set
        if not request_id_var.get():
            request_id_var.set(generate_request_id())
        
        return await func(*args, **kwargs)
    
    return wrapper


class LogContext:
    """Context manager for temporarily setting log context."""
    
    def __init__(self, **kwargs):
        self.context = kwargs
        self.tokens = {}
    
    def __enter__(self):
        """Set context variables."""
        for key, value in self.context.items():
            if key == 'trace_id':
                self.tokens['trace_id'] = trace_id_var.set(value)
            elif key == 'session_id':
                self.tokens['session_id'] = session_id_var.set(value)
            elif key == 'request_id':
                self.tokens['request_id'] = request_id_var.set(value)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Reset context variables."""
        for key, token in self.tokens.items():
            if key == 'trace_id':
                trace_id_var.reset(token)
            elif key == 'session_id':
                session_id_var.reset(token)
            elif key == 'request_id':
                request_id_var.reset(token)


# Structured log event types for consistency
class LogEvent:
    """Standard log event types."""
    
    # Process lifecycle events
    PROCESS_SPAWN_START = "process.spawn.start"
    PROCESS_SPAWN_SUCCESS = "process.spawn.success"
    PROCESS_SPAWN_ERROR = "process.spawn.error"
    PROCESS_TERMINATE_START = "process.terminate.start"
    PROCESS_TERMINATE_SUCCESS = "process.terminate.success"
    PROCESS_TERMINATE_ERROR = "process.terminate.error"
    PROCESS_STATE_CHANGE = "process.state.change"
    
    # WebSocket events
    WEBSOCKET_CONNECT = "websocket.connect"
    WEBSOCKET_DISCONNECT = "websocket.disconnect"
    WEBSOCKET_MESSAGE_RECEIVED = "websocket.message.received"
    WEBSOCKET_MESSAGE_SENT = "websocket.message.sent"
    WEBSOCKET_ERROR = "websocket.error"
    
    # Authentication events
    AUTH_ATTEMPT = "auth.attempt"
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    AUTH_TOTP_GENERATED = "auth.totp.generated"
    
    # Session events  
    SESSION_CREATE = "session.create"
    SESSION_VALIDATE = "session.validate"
    SESSION_EXPIRE = "session.expire"
    
    # Performance events
    PERFORMANCE_SLOW_OPERATION = "performance.slow_operation"
    PERFORMANCE_RESOURCE_LIMIT = "performance.resource_limit"


def log_event(logger: Union[logging.Logger, StructuredLogger], 
              event_type: str, 
              message: str, 
              level: int = logging.INFO,
              **extra_fields):
    """Log a structured event."""
    if isinstance(logger, logging.Logger):
        logger = StructuredLogger(logger)
    
    extra_fields['event_type'] = event_type
    extra_fields['event_timestamp'] = time.time()
    
    logger._log_with_context(level, message, extra_fields=extra_fields)