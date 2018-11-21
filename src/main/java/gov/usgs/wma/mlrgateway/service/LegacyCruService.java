package gov.usgs.wma.mlrgateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import gov.usgs.wma.mlrgateway.FeignBadResponseWrapper;
import gov.usgs.wma.mlrgateway.SiteReport;
import gov.usgs.wma.mlrgateway.StepReport;
import gov.usgs.wma.mlrgateway.client.LegacyCruClient;
import gov.usgs.wma.mlrgateway.controller.BaseController;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class LegacyCruService {
	private LegacyCruClient legacyCruClient;
	private Logger log = LoggerFactory.getLogger(LegacyCruService.class);
		
	public static final String SITE_ADD_STEP = "Site Add";
	public static final String SITE_ADD_SUCCESSFULL = "Site Added Successfully";
	public static final String SITE_ADD_FAILED = "Site add failed";
	public static final String SITE_UPDATE_STEP = "Site Update";
	public static final String SITE_UPDATE_SUCCESSFULL = "Site Updated Successfully.";
	public static final String SITE_UPDATE_FAILED = "Site update failed";
	public static final String SITE_GET_STEP = "Location Get by AgencyCode and SiteNumber";
	public static final String SITE_GET_SUCCESSFULL = "Location Get Successful";
	public static final String SITE_GET_DOES_NOT_EXIST = "Requested Location Not Found";
	public static final String SITE_GET_STEP_FAILED = "{\"error\":{\"message\": \"Unable to read Legacy CRU output.\"}}";
	
	public LegacyCruService(LegacyCruClient legacyCruClient){
		this.legacyCruClient = legacyCruClient;
	}
	
	public String addTransaction(Object agencyCode, Object siteNumber, String json, SiteReport siteReport) {
		try {
			ResponseEntity<String> cruResp = legacyCruClient.createMonitoringLocation(json);
			int cruStatus = cruResp.getStatusCodeValue();
			siteReport.addStepReport(new StepReport(SITE_ADD_STEP, cruStatus, 201 == cruStatus ? true : false, 201 == cruStatus ? SITE_ADD_SUCCESSFULL : cruResp.getBody()));
			return cruResp.getBody();
		} catch (Exception e) {
			siteReport.addStepReport(new StepReport(SITE_ADD_STEP, HttpStatus.SC_INTERNAL_SERVER_ERROR, false, SITE_ADD_FAILED));
			log.error(SITE_ADD_STEP + ": " + SITE_ADD_FAILED + ":" +  e.getMessage());			
			throw new FeignBadResponseWrapper(HttpStatus.SC_INTERNAL_SERVER_ERROR, null, "{\"error_message\": \"" + SITE_ADD_FAILED + "\"}");	
		}
	}
	
	public String updateTransaction(Object agencyCode, Object siteNumber, String json, SiteReport siteReport) {
		try {
			ResponseEntity<String> cruResp = legacyCruClient.patchMonitoringLocation(json);
			int cruStatus = cruResp.getStatusCodeValue();
			siteReport.addStepReport(new StepReport(SITE_UPDATE_STEP, cruStatus, 200 == cruStatus ? true : false, 200 == cruStatus ? SITE_UPDATE_SUCCESSFULL : cruResp.getBody()));
			return cruResp.getBody();
		} catch (Exception e){
			siteReport.addStepReport(new StepReport(SITE_UPDATE_STEP, HttpStatus.SC_INTERNAL_SERVER_ERROR, false, SITE_UPDATE_FAILED));
			log.error(SITE_UPDATE_STEP + ": " + SITE_UPDATE_FAILED + ":" +  e.getMessage());			
			throw new FeignBadResponseWrapper(HttpStatus.SC_INTERNAL_SERVER_ERROR, null, "{\"error_message\": \"" + SITE_UPDATE_FAILED + "\"}");
		}
	}
	
	public Map<String, Object> getMonitoringLocation(Object agencyCode, Object siteNumber, boolean isAddTransaction, SiteReport siteReport) {
		Map<String, Object> site = new HashMap<>();
		ObjectMapper mapper = new ObjectMapper();
		
		ResponseEntity<String> cruResp = legacyCruClient.getMonitoringLocation((String)agencyCode, (String)siteNumber);
		int cruStatus = cruResp.getStatusCodeValue();
		boolean isSuccess = true;
		String preValMsg = "";
		
		if (cruStatus == 404) {
			if (isAddTransaction) {
				isSuccess = true;
				preValMsg = "Duplicate agency code/site number check: ";
			} else {
				isSuccess = false;
			}
			siteReport.addStepReport(new StepReport(preValMsg + SITE_GET_STEP, cruStatus, isSuccess, SITE_GET_DOES_NOT_EXIST));
  		} else {

			try {
				site = mapper.readValue(cruResp.getBody(), Map.class);
			} catch (Exception e) {
				siteReport.addStepReport(new StepReport(SITE_GET_STEP, HttpStatus.SC_INTERNAL_SERVER_ERROR, false, SITE_GET_STEP_FAILED));
				log.error(SITE_GET_STEP + ": " + SITE_GET_STEP_FAILED + ":" +  e.getMessage());			
				throw new FeignBadResponseWrapper(HttpStatus.SC_INTERNAL_SERVER_ERROR, null, SITE_GET_STEP_FAILED);
			}

			siteReport.addStepReport(new StepReport(SITE_GET_STEP, cruStatus, 200 == cruStatus ? true : false, 200 == cruStatus ? SITE_GET_SUCCESSFULL : cruResp.getBody()));
		}
		return site;
	}
}
