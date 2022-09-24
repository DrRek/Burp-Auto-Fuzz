from javax.swing import JTable;
from javax.swing.table import AbstractTableModel;

class HistoryTable(JTable):
    def __init__(self, extender):
        self._extender = extender

        model = HistoryTableModel(extender)
        self.setModel(model)
    
    def changeSelection(self, row, col, toggle, extend):
        self.getModel().selectJob(row)        
        JTable.changeSelection(self, row, col, toggle, extend)

    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        jobEntry = self._extender.selectJobByRow(row)
        
        JTable.changeSelection(self, row, col, toggle, extend)

    def updateTable(self, row, row2):
        self.getModel().fireTableRowsInserted(row, row2)

class HistoryTableModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getRowCount(self):
        return self._extender.getJobsCount()

    def getColumnCount(self):
        return 5

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Id"
        if columnIndex == 1:
            return "Tool"
        if columnIndex == 2:
            return "Type"
        if columnIndex == 3:
            return "Status"
        if columnIndex == 4:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        jobEntry = self._extender.getJobByRow(rowIndex)
        if columnIndex == 0:
            return jobEntry._id
        if columnIndex == 1:
            return self._extender._callbacks.getToolName(jobEntry._tool)
        if columnIndex == 2:
            return jobEntry._analyzedRequest.getMethod()
        if columnIndex == 3:
            return jobEntry._status
        if columnIndex == 4:
            return jobEntry._analyzedRequest.getUrl()
        return "COLUMN NOT RESOLVED"
