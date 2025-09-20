"""Approval workflow views."""

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from ..auth import require_auth, require_manager_or_admin
from ..auth.session import get_current_user
from ..models import Approval, ApprovalType, Secret
from ..services.approval_service import get_approval_service

approvals_bp = Blueprint("approvals", __name__)


@approvals_bp.route("/")
@require_manager_or_admin
def index():
    """List all pending approvals for the current user."""
    user = get_current_user()
    approval_service = get_approval_service()

    # Get pending approvals this user can approve
    pending_approvals = approval_service.get_pending_approvals_for_user(user)

    # Get user's own requests
    my_requests = approval_service.get_user_requests(user, limit=20)

    return render_template(
        "approvals/index.html",
        pending_approvals=pending_approvals,
        my_requests=my_requests,
        user=user,
    )


@approvals_bp.route("/<int:approval_id>")
@require_auth
def detail(approval_id):
    """View approval details."""
    user = get_current_user()
    approval = Approval.query.get_or_404(approval_id)

    # Check if user can view this approval
    can_approve = user.can_manage_environment(approval.environment_name)
    is_requester = approval.requester_id == user.id

    if not (can_approve or is_requester or user.is_admin):
        flash("Access denied to this approval", "error")
        return redirect(url_for("approvals.index"))

    # Get related secret if applicable
    secret = None
    if approval.resource_type == "secret" and approval.resource_id:
        secret = Secret.query.get(approval.resource_id)

    return render_template(
        "approvals/detail.html",
        approval=approval,
        secret=secret,
        can_approve=can_approve,
        is_requester=is_requester,
        user=user,
    )


@approvals_bp.route("/<int:approval_id>/approve", methods=["POST"])
@require_manager_or_admin
def approve(approval_id):
    """Approve a pending request."""
    user = get_current_user()
    approval_service = get_approval_service()

    try:
        comment = request.form.get("comment", "").strip()
        approval = approval_service.approve_request(approval_id, user, comment)

        flash("Request approved successfully", "success")

        # If it's a rotation approval, offer to execute it
        if approval.approval_type == ApprovalType.SECRET_ROTATION:
            return redirect(url_for("approvals.execute", approval_id=approval.id))

    except ValueError as e:
        flash(f"Failed to approve request: {str(e)}", "error")
    except Exception as e:
        current_app.logger.error(f"Error approving request {approval_id}: {str(e)}")
        flash("An error occurred while approving the request", "error")

    return redirect(url_for("approvals.detail", approval_id=approval_id))


@approvals_bp.route("/<int:approval_id>/reject", methods=["POST"])
@require_manager_or_admin
def reject(approval_id):
    """Reject a pending request."""
    user = get_current_user()
    approval_service = get_approval_service()

    try:
        comment = request.form.get("comment", "").strip()
        if not comment:
            flash("A comment is required when rejecting a request", "error")
            return redirect(url_for("approvals.detail", approval_id=approval_id))

        approval_service.reject_request(approval_id, user, comment)
        flash("Request rejected", "info")

    except ValueError as e:
        flash(f"Failed to reject request: {str(e)}", "error")
    except Exception as e:
        current_app.logger.error(f"Error rejecting request {approval_id}: {str(e)}")
        flash("An error occurred while rejecting the request", "error")

    return redirect(url_for("approvals.detail", approval_id=approval_id))


@approvals_bp.route("/<int:approval_id>/execute", methods=["GET", "POST"])
@require_manager_or_admin
def execute(approval_id):
    """Execute an approved request."""
    user = get_current_user()
    approval = Approval.query.get_or_404(approval_id)

    # Check permissions
    if not user.can_manage_environment(approval.environment_name):
        flash("Access denied to execute this approval", "error")
        return redirect(url_for("approvals.index"))

    if request.method == "POST":
        approval_service = get_approval_service()

        try:
            result = approval_service.execute_approved_rotation(approval_id, user)

            if result["success"]:
                flash(result["message"], "success")
                return redirect(url_for("secrets.detail", id=result["secret_id"]))
            else:
                flash(f"Execution failed: {result['error']}", "error")

        except ValueError as e:
            flash(f"Cannot execute: {str(e)}", "error")
        except Exception as e:
            current_app.logger.error(
                f"Error executing approval {approval_id}: {str(e)}"
            )
            flash("An error occurred while executing the request", "error")

        return redirect(url_for("approvals.detail", approval_id=approval_id))

    # GET request - show execution confirmation
    secret = None
    if approval.resource_type == "secret" and approval.resource_id:
        secret = Secret.query.get(approval.resource_id)

    return render_template(
        "approvals/execute.html", approval=approval, secret=secret, user=user
    )


@approvals_bp.route("/api/count")
@require_auth
def api_count():
    """API endpoint to get pending approval count for current user."""
    user = get_current_user()
    approval_service = get_approval_service()

    pending_count = len(approval_service.get_pending_approvals_for_user(user))

    return jsonify({"pending_count": pending_count})


@approvals_bp.route("/request/rotation/<int:secret_id>", methods=["GET", "POST"])
@require_auth
def request_rotation(secret_id):
    """Request approval for secret rotation."""
    user = get_current_user()
    secret = Secret.query.get_or_404(secret_id)

    # Check if user can access this secret
    if not user.can_access_environment(secret.environment.name):
        flash("Access denied to this secret", "error")
        return redirect(url_for("secrets.index"))

    # Check if approval is needed
    if not user.requires_approval_for_rotation(secret.environment.name):
        flash("Approval not required for rotation in this environment", "info")
        return redirect(url_for("secrets.rotate", id=secret_id))

    if request.method == "POST":
        approval_service = get_approval_service()

        try:
            reason = request.form.get("reason", "").strip()
            if not reason:
                flash("A reason is required for approval requests", "error")
                return render_template(
                    "approvals/request_rotation.html", secret=secret, user=user
                )

            # Collect rotation details from form
            rotation_details = {
                "generation_method": request.form.get("generation_method", "manual"),
                "new_value": request.form.get("new_value", ""),
                "length": request.form.get("length", type=int),
                "complexity": request.form.get("complexity", "complex"),
                "immediate_activate": "immediate_activate" in request.form,
                "auto_sync": "auto_sync" in request.form,
            }

            approval = approval_service.request_rotation_approval(
                secret=secret,
                requester=user,
                reason=reason,
                rotation_details=rotation_details,
            )

            flash(f"Rotation approval request submitted (ID: {approval.id})", "success")
            return redirect(url_for("approvals.detail", approval_id=approval.id))

        except ValueError as e:
            flash(f"Failed to submit request: {str(e)}", "error")
        except Exception as e:
            current_app.logger.error(f"Error requesting rotation approval: {str(e)}")
            flash("An error occurred while submitting the request", "error")

    return render_template("approvals/request_rotation.html", secret=secret, user=user)
