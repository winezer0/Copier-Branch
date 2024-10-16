package com.whiteoaksecurity.copier.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.whiteoaksecurity.copier.Rule;
import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

@JsonIgnoreProperties({"ruleType", "locations", "columnCount", "rowCount", "tableModelListeners"})
public class RulesTableModel extends AbstractTableModel {
	
	String ruleType = "Rule";
	private final String[] columnNames = {"EnabledRule", "EnabledBase64", "LocateRule","JsonFormat", "Location", "Match", "Replace", "Type", "Comment"};
	String[] locations;
	private ArrayList<Rule> data = new ArrayList<>();

	public RulesTableModel() {
		this.locations = new String[0];
	}
	
	public String getRuleType() {
		return this.ruleType;
	}
	
	public String[] getLocations() {
		return this.locations;
	}
	
	@Override
	public int getRowCount() {
		return data.size();
	}
	
	public ArrayList<Rule> getData() {
		return data;
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}
	
	@Override
	public String getColumnName(int columnIndex) {
		return columnNames[columnIndex];
	}
	
	@Override
    public Class getColumnClass(int columnIndex) {
        return switch (columnIndex) {
			case 0 -> Boolean.class;
			case 1 -> Boolean.class;
			case 2 -> Boolean.class;
			case 3 -> Boolean.class;
			case 4 -> String.class;
			case 5 -> String.class;
			case 6 -> String.class;
			case 7 -> String.class;
			case 8 -> String.class;
			default -> String.class;
        };
    }

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Rule r = this.data.get(rowIndex);
		
		return switch (columnIndex) {
			case 0 -> r.isEnabledRule();
			case 1 -> r.isEnabledBase64();
			case 2 -> r.isLocateRule();
			case 3 -> r.isJsonFormat();
			case 4 -> locations[r.getLocation()];
			case 5 -> r.getMatch();
			case 6 -> r.getReplace();
			case 7 -> r.isRegex() ? "Regex" : "Literal";
			case 8 -> r.getComment();
			default -> "";
		};
	}
	
	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		Rule r = data.get(rowIndex);
		
		switch (columnIndex) {
			case 0 -> r.setIsEnabledRule((Boolean) value);
			case 1 -> r.setIsEnabledBase64((Boolean) value);
			case 2 -> r.setIsLocateRule((Boolean) value);
			case 3 -> r.setIsJsonFormat((Boolean) value);
		}
	}
	
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex <= 3) {
			return true;
		}
		return false;
	}
	
	public void add(Rule r) {
		data.add(r);
	}
}
