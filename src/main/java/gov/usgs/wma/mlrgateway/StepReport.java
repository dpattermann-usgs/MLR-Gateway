package gov.usgs.wma.mlrgateway;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class StepReport {

	private String name;
	private Integer httpStatus;
	private boolean success;
	private String details;

	public StepReport() {}

	public StepReport(String name, Integer httpStatus, boolean success, String details) {
		this.name = name;
		this.httpStatus = httpStatus;
		this.success = success;
		this.details = details;
	}
	
	public StepReport(StepReport stepReport) {
		this.name = stepReport.name;
		this.httpStatus = stepReport.httpStatus;
		this.success = stepReport.success;
		this.details = stepReport.details;
	}

	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public Integer getHttpStatus() {
		return httpStatus;
	}
	public void setHttpStatus(Integer httpStatus) {
		this.httpStatus = httpStatus;
	}
	public boolean isSuccess() {
		return success;
	}

	public void isSuccess(boolean success) {
		this.success = success;
	}

	public String getDetails() {
		return details;
	}
	public void setDetails(String details) {
		this.details = details;
	}

}
