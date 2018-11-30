package gov.usgs.wma.mlrgateway.controller;

import java.util.Collections;
import java.util.Comparator;

import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import gov.usgs.wma.mlrgateway.FeignBadResponseWrapper;
import gov.usgs.wma.mlrgateway.GatewayReport;
import gov.usgs.wma.mlrgateway.StepReport;
import gov.usgs.wma.mlrgateway.workflow.ExportWorkflowService;
import gov.usgs.wma.mlrgateway.service.FileExportService;
import gov.usgs.wma.mlrgateway.service.NotificationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

@Api(tags={"Export Workflow"})
@RestController
public class ExportWorkflowController extends BaseController {
	private ExportWorkflowService export;
	public static final String COMPLETE_WORKFLOW = "Complete Export Workflow";
	public static final String EXPORT_WORKFLOW_SUBJECT = "Transaction File Generation for Requested Location";
	
	@Autowired
	public ExportWorkflowController(ExportWorkflowService export, NotificationService notificationService) {
		super(notificationService);
		this.export = export;
	}

	@ApiOperation(value="Perform the entire workflow, including retrieving record from Legacy CRU and returning the Transaction file.")
	@ApiResponses(value={@ApiResponse(code=200, message="OK"),
			@ApiResponse(code=400, message="Bad Request"),
			@ApiResponse(code=401, message="Unauthorized"),
			@ApiResponse(code=403, message="Forbidden")})
	@PreAuthorize("hasPermission(null, null)")
	@PostMapping("/legacy/location/{agencyCode}/{siteNumber}")
	public GatewayReport exportWorkflow(@PathVariable("agencyCode") String agencyCode, @PathVariable("siteNumber") String siteNumber, HttpServletResponse response) {
		setReport(new GatewayReport(COMPLETE_WORKFLOW, null));
		try {
			export.exportWorkflow(agencyCode, siteNumber);
			ExportWorkflowController.addWorkflowStepReport(new StepReport(COMPLETE_WORKFLOW, HttpStatus.SC_OK, true, FileExportService.EXPORT_SUCCESSFULL));
		} catch (Exception e) {
			if (e instanceof FeignBadResponseWrapper) {
				int status = ((FeignBadResponseWrapper) e).getStatus();
				ExportWorkflowController.addWorkflowStepReport(new StepReport(COMPLETE_WORKFLOW, status, false, ((FeignBadResponseWrapper) e).getBody()));
			} else {
				int status = HttpStatus.SC_INTERNAL_SERVER_ERROR;
				ExportWorkflowController.addWorkflowStepReport(new StepReport(COMPLETE_WORKFLOW, status, false,  e.getLocalizedMessage()));
			}
		}
		
		//Send Notification
		notificationStep(EXPORT_WORKFLOW_SUBJECT);
		
		//Return Report
		GatewayReport rtn = getReport();
		StepReport maxStatusStep = Collections.max(rtn.getWorkflowSteps(), Comparator.comparing(s -> s.getHttpStatus()));
		response.setStatus(maxStatusStep.getHttpStatus());
		remove();
		return rtn;
	}	
}
