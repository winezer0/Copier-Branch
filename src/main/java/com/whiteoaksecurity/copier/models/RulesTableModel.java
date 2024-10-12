package com.whiteoaksecurity.copier.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.whiteoaksecurity.copier.Rule;
import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

@JsonIgnoreProperties({"ruleType", "locations", "columnCount", "rowCount", "tableModelListeners"})
public class RulesTableModel extends AbstractTableModel {
	
	String ruleType = "Rule";
	private final String[] columnNames = {"EnabledBase64", "StoreLocate", "Location", "Match", "Replace", "Type", "Comment"};
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
			case 2 -> String.class;
			case 3 -> String.class;
			case 4 -> String.class;
			case 5 -> String.class;
			case 6 -> String.class;
			default -> String.class;
        };
    }

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Rule r = this.data.get(rowIndex);
		
		return switch (columnIndex) {
			case 0 -> r.isEnabledBase64();
			case 1 -> r.isStoreLocate();
			case 2 -> locations[r.getLocation()];
			case 3 -> r.getMatch();
			case 4 -> r.getReplace();
			case 5 -> r.isRegex() ? "Regex" : "Literal";
			case 6 -> r.getComment();
			default -> "";
		};
	}
	
	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		Rule r = data.get(rowIndex);
		
		switch (columnIndex) {
			case 0 -> r.setIsEnabledBase64((Boolean) value);
		}
	}
	
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex == 0) {
			return true;
		}
		return false;
	}
	
	public void add(Rule r) {
		data.add(r);
	}
}
