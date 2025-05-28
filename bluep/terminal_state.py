"""Terminal state management with explicit state machine."""

import asyncio
import logging
from enum import Enum, auto
from typing import Dict, Set, Optional, Callable, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class TerminalState(Enum):
    """Possible states for a terminal process."""
    
    INITIALIZING = auto()  # Terminal is being set up
    SPAWNING = auto()      # Process is being spawned
    ACTIVE = auto()        # Terminal is running and responsive
    TERMINATING = auto()   # Terminal is being shut down
    TERMINATED = auto()    # Terminal has been cleaned up
    ERROR = auto()         # Terminal encountered an error


class StateTransition:
    """Represents a valid state transition."""
    
    def __init__(self, from_state: TerminalState, to_state: TerminalState, 
                 condition: Optional[Callable[[], bool]] = None):
        self.from_state = from_state
        self.to_state = to_state
        self.condition = condition


class TerminalStateMachine:
    """Manages terminal state transitions with validation and logging."""
    
    # Valid state transitions
    TRANSITIONS = [
        StateTransition(TerminalState.INITIALIZING, TerminalState.SPAWNING),
        StateTransition(TerminalState.SPAWNING, TerminalState.ACTIVE),
        StateTransition(TerminalState.SPAWNING, TerminalState.ERROR),
        StateTransition(TerminalState.ACTIVE, TerminalState.TERMINATING),
        StateTransition(TerminalState.ACTIVE, TerminalState.ERROR),
        StateTransition(TerminalState.TERMINATING, TerminalState.TERMINATED),
        StateTransition(TerminalState.TERMINATING, TerminalState.ERROR),
        StateTransition(TerminalState.ERROR, TerminalState.TERMINATING),
        StateTransition(TerminalState.ERROR, TerminalState.TERMINATED),
    ]
    
    def __init__(self, terminal_id: str, trace_id: Optional[str] = None):
        self.terminal_id = terminal_id
        self.trace_id = trace_id or terminal_id
        self.current_state = TerminalState.INITIALIZING
        self.state_history: List[tuple[TerminalState, datetime]] = [
            (self.current_state, datetime.now())
        ]
        self.transition_callbacks: Dict[TerminalState, List[Callable]] = {}
        self._lock = asyncio.Lock()
        
        # Build transition map for efficient lookup
        self._transition_map: Dict[TerminalState, Set[TerminalState]] = {}
        for transition in self.TRANSITIONS:
            if transition.from_state not in self._transition_map:
                self._transition_map[transition.from_state] = set()
            self._transition_map[transition.from_state].add(transition.to_state)
    
    async def transition_to(self, new_state: TerminalState, 
                           metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Attempt to transition to a new state.
        
        Returns True if transition was successful, False otherwise.
        """
        async with self._lock:
            if not self._is_valid_transition(self.current_state, new_state):
                logger.warning(
                    f"[{self.trace_id}] Invalid state transition attempted: "
                    f"{self.current_state.name} -> {new_state.name} for terminal {self.terminal_id}"
                )
                return False
            
            old_state = self.current_state
            self.current_state = new_state
            self.state_history.append((new_state, datetime.now()))
            
            logger.info(
                f"[{self.trace_id}] Terminal {self.terminal_id} transitioned: "
                f"{old_state.name} -> {new_state.name}",
                extra={
                    "terminal_id": self.terminal_id,
                    "trace_id": self.trace_id,
                    "old_state": old_state.name,
                    "new_state": new_state.name,
                    "metadata": metadata
                }
            )
            
            # Execute callbacks for this state
            if new_state in self.transition_callbacks:
                for callback in self.transition_callbacks[new_state]:
                    try:
                        await callback(self.terminal_id, old_state, new_state, metadata)
                    except Exception as e:
                        logger.error(
                            f"[{self.trace_id}] Error in state transition callback: {e}",
                            exc_info=True
                        )
            
            return True
    
    def _is_valid_transition(self, from_state: TerminalState, 
                           to_state: TerminalState) -> bool:
        """Check if a state transition is valid."""
        return (from_state in self._transition_map and 
                to_state in self._transition_map[from_state])
    
    def on_state_enter(self, state: TerminalState, 
                      callback: Callable[[str, TerminalState, TerminalState, Optional[Dict]], Any]):
        """Register a callback to be called when entering a specific state."""
        if state not in self.transition_callbacks:
            self.transition_callbacks[state] = []
        self.transition_callbacks[state].append(callback)
    
    def get_state(self) -> TerminalState:
        """Get current state."""
        return self.current_state
    
    def is_active(self) -> bool:
        """Check if terminal is in an active state."""
        return self.current_state == TerminalState.ACTIVE
    
    def is_terminated(self) -> bool:
        """Check if terminal has been terminated."""
        return self.current_state in (TerminalState.TERMINATED, TerminalState.ERROR)
    
    def can_accept_input(self) -> bool:
        """Check if terminal can accept input."""
        return self.current_state == TerminalState.ACTIVE
    
    def can_terminate(self) -> bool:
        """Check if terminal can be terminated."""
        return self.current_state in (TerminalState.ACTIVE, TerminalState.ERROR)
    
    def get_lifetime_seconds(self) -> float:
        """Get the total lifetime of the terminal in seconds."""
        if self.state_history:
            start_time = self.state_history[0][1]
            return (datetime.now() - start_time).total_seconds()
        return 0.0
    
    def get_state_duration(self, state: TerminalState) -> float:
        """Get total time spent in a specific state."""
        total_duration = 0.0
        
        for i in range(len(self.state_history)):
            if self.state_history[i][0] == state:
                start_time = self.state_history[i][1]
                # Find when we left this state
                if i + 1 < len(self.state_history):
                    end_time = self.state_history[i + 1][1]
                else:
                    # Still in this state
                    end_time = datetime.now()
                total_duration += (end_time - start_time).total_seconds()
        
        return total_duration