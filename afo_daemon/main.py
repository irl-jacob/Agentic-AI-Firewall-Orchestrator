import asyncio
import signal
import sys

import structlog

from backend.nftables import NftablesBackend
from db.database import get_session
from services.firewall import FirewallService
from services.learning_service import get_learning_service

# Configure logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger()


class AFODaemon:
    """
    Main daemon class for Autonomous Firewall Orchestrator.
    """

    def __init__(self):
        self.running = False
        self.service: FirewallService | None = None
        self.learning_service = None

    async def setup(self) -> None:
        """Initialize resources."""
        logger.info("daemon_startup", status="initializing")

        # Initialize Backend
        backend = NftablesBackend()

        # Initialize Service (with a session)
        # Note: For a long-running daemon, we might need better session management.
        # Ideally, we create a new session for each unit of work.
        # For the skeleton, we'll just verify we can get one.
        session_gen = get_session()
        try:
            self.session = await anext(session_gen)
            self.service = FirewallService(backend, self.session)

            # Initialize Learning Service
            self.learning_service = get_learning_service(self.session, self.service)
            await self.learning_service.start()

            logger.info("daemon_startup", status="resources_ready")
        except Exception as e:
            logger.error("daemon_startup_failed", error=str(e))
            sys.exit(1)

    async def shutdown(self) -> None:
        """Cleanup resources."""
        logger.info("daemon_shutdown", status="stopping")

        # Stop learning service
        if self.learning_service:
            await self.learning_service.stop()

        # In a real app, close DB connections, etc.
        logger.info("daemon_shutdown", status="completed")

    async def run_loop(self) -> None:
        """Main execution loop."""
        self.running = True
        logger.info("daemon_loop", status="started")

        while self.running:
            try:
                # Placeholder for autonomous logic (Phase 4)
                # For now, just log a heartbeat
                logger.info("daemon_heartbeat", status="alive")

                # Check backend status
                if self.service:
                    status = await self.service.backend.get_status()
                    logger.debug("backend_status", status=status)

                # Log learning service status
                if self.learning_service:
                    learning_status = await self.learning_service.get_status()
                    logger.debug("learning_status", **learning_status)

                await asyncio.sleep(60)  # Run every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("daemon_loop_error", error=str(e))
                await asyncio.sleep(5)  # Backoff on error

    def handle_signal(self) -> None:
        """Handle termination signals."""
        logger.info("signal_received", action="stopping_loop")
        self.running = False


async def run_daemon() -> None:
    """Async entry point."""
    daemon = AFODaemon()

    # Setup signal handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, daemon.handle_signal)

    await daemon.setup()

    try:
        await daemon.run_loop()
    finally:
        await daemon.shutdown()


def main() -> None:
    """CLI entry point."""
    try:
        asyncio.run(run_daemon())
    except KeyboardInterrupt:
        pass  # Handled by signal handler usually, but safe fallback

if __name__ == "__main__":
    main()
