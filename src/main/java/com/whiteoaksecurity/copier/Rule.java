package com.whiteoaksecurity.copier;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@JsonIgnoreProperties({"REGEX", "LITERAL", "pattern"})
public class Rule {
	public static final boolean REGEX = true;
	public static final boolean LITERAL = false;

	private boolean enabledRule;
	private boolean enabledBase64;
	private int location;
	private String match;
	private Pattern pattern;
	private String replace;
	private boolean regex;
	private boolean locateRule;
	private boolean jsonFormat;
	private String comment;
	
	@JsonCreator
	public Rule(@JsonProperty("enabledRule") boolean enabledRule,
				@JsonProperty("enabledBase64") boolean enabledBase64,
				@JsonProperty("locateRule") boolean locateRule,
				@JsonProperty("jsonFormat") boolean jsonFormat,
				@JsonProperty("location") int location,
				@JsonProperty("match") String match,
				@JsonProperty("replace") String replace,
				@JsonProperty("regex") boolean regex,
				@JsonProperty("comment") String comment) {
		this.enabledRule = enabledRule;
		this.enabledBase64 = enabledBase64;
		this.location = location;
		this.match = match;
		this.replace = replace;
		this.regex = regex;
		this.locateRule = locateRule;
		this.jsonFormat = jsonFormat;
		this.comment = comment;
		
		int flags = Pattern.DOTALL;
		
		if (this.regex == LITERAL) {
			flags = flags | Pattern.LITERAL;
		}
		
		try {
			this.pattern = Pattern.compile(match, flags);
		} catch (PatternSyntaxException e) {
			this.pattern = null;
//			this.enabledBase64 = false;
			this.enabledRule = false;
		}
	}
	
	public boolean isEnabledBase64() {
		return this.enabledBase64;
	}

	public boolean isEnabledRule() {
		return this.enabledRule;
	}

	public int getLocation() {
		return this.location;
	}
	
	public String getMatch() {
		return this.match;
	}
	
	public Pattern getPattern() {
		return this.pattern;
	}
	
	public String getReplace() {
		return this.replace;
	}
	
	public boolean isRegex() {
		return this.regex;
	}
	
	public boolean isLocateRule() {
		return this.locateRule;
	}

	public boolean isJsonFormat() {
		return this.jsonFormat;
	}
	
	public String getComment() {
		return this.comment;
	}
	
	public String toString(String[] locations) {
		return locations[this.location] + ": " + this.match + " -> " + this.replace;
	}

	public String toString() {
		return this.location + ": " + this.match + " -> " + this.replace;
	}
	
	public void setIsEnabledBase64(boolean enabledBase64) {
		this.enabledBase64 = enabledBase64;
//		this.compile(this.match, false);
	}

	public void setIsEnabledRule(boolean enabledRule) {
		this.enabledRule = enabledRule;
		this.compile(this.match, false);
	}

	public void setLocation(int location) {
		this.location = location;
	}
	
	public void setMatch(String match) {
		this.match = match;
		this.compile(match, false);
	}
	
	public void setReplace(String replace) {
		this.replace = replace;
	}
	
	public void setIsRegex(boolean type) {
		this.regex = type;
	}
	
	public void setIsLocateRule(boolean locateRule) {
		this.locateRule = locateRule;
	}

	public void setIsJsonFormat(boolean jsonFormat) {
		this.jsonFormat = jsonFormat;
	}
	
	public void setComment(String comment) {
		this.comment = comment;
	}
	
	public void compile(String match, boolean caseSensitive) {
		int flags = Pattern.DOTALL;
		if (!caseSensitive) {
			flags = flags | Pattern.CASE_INSENSITIVE;
		}
		
		if (this.regex == LITERAL) {
			flags = flags | Pattern.LITERAL;
		}
		
		try {
			this.pattern = Pattern.compile(match, flags);
		} catch (PatternSyntaxException e) {
			this.pattern = null;
//			this.enabledBase64 = false;
			this.enabledRule = false;
		}
	}
}
