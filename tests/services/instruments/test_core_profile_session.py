from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import (
    CoreProfileSessionTap,
)


def test_stackshot(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test getting stackshot.
    """
    with CoreProfileSessionTap(dvt, CoreProfileSessionTap.get_time_config(dvt)) as tap:
        data = tap.get_stackshot()

    assert "Darwin Kernel" in data["osversion"]
    # Constant kernel task data.
    assert data["task_snapshots"][0]["task_snapshot"]["ts_pid"] == 0
    assert data["task_snapshots"][0]["task_snapshot"]["ts_p_comm"] == "kernel_task"
