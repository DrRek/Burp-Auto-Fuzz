from javax.swing import JTable;
from javax.swing.table import AbstractTableModel;
from java.awt.event import MouseListener
import traceback

class JobTable(JTable):
    def __init__(self, extender):
        self._extender = extender

        model = JobTableModel(extender)
        self.setModel(model)

        self.addMouseListener(JobTableMouseListener(extender))

    def updateTable(self):
        self.getModel().fireTableDataChanged()

class JobTableModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getRowCount(self):
        try:
            return self._extender.getSelectedJob().getFuzLength()
        except:
            return 0

    def getColumnCount(self):
        return 6

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Id"
        if columnIndex == 1:
            return "parameter"
        if columnIndex == 2:
            return "payload"
        if columnIndex == 3:
            return "status"
        if columnIndex == 4:
            return "length"
        if columnIndex == 5:
            return "time"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        try:
            fuzEntry = self._extender.getSelectedJob().getFuzByRow(rowIndex)
            if columnIndex == 0:
                return fuzEntry["id"]
            if columnIndex == 1:
                try:
                    return fuzEntry["parameter"].getName()
                except KeyError:
                    return "NO_CHANGE"
            if columnIndex == 2:
                try:
                    return fuzEntry["parameter"].getValue()
                except KeyError:
                    return "NO_CHANGE"
            if columnIndex == 3:
                return fuzEntry["reqResp"].getStatusCode()
            if columnIndex == 4:
                return len(fuzEntry["reqResp"].getResponse())
            if columnIndex == 5:
                headers = fuzEntry["analyzedResp"].getHeaders()
                for header in headers:
                    if header.startswith("Date: "):
                        return header[6:-1] 
                return "n/a"
            return ""
        except Exception as e:
            self._extender.log(e, True)
            traceback.print_exc()
            return "Exception"

class JobTableMouseListener(MouseListener):
    def __init__(self, extender):
        self._extender = extender
    
    def getClickedIndex(self, event):
        """Returns the value of the first column of the table row that was
        clicked. This is not the same as the row index because the table
        can be sorted."""
        # get the event source, the table in this case.
        tbl = event.getSource()
        # get the clicked row
        row = tbl.getSelectedRow()
        # get the first value of clicked row
        return tbl.getValueAt(row, 0)
        # return event.getSource.getValueAt(event.getSource().getSelectedRow(), 0)

    def getClickedRow(self, event):
        """Returns the complete clicked row."""
        """Returns the complete clicked row."""
        tbl = event.getSource()
        mdl = tbl.getModel()
        row = tbl.convertRowIndexToModel(tbl.getSelectedRow())
        assert isinstance(mdl, JobTableModel)
        return self._extender.getSelectedJob().getFuzByRow(row)

    # event.getClickCount() returns the number of clicks.
    def mouseClicked(self, event):
        try:
            if event.getClickCount() == 2:
                self._extender.openRequestResponsePanel(self.getClickedRow(event))
                return
        except Exception as e:
            self._extender.log(e, True)

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass    
    
    def mousePressed(self, event):
        # print "mouse pressed", event.getClickCount()
        pass

    def mouseReleased(self, event):
        # print "mouse released", event.getClickCount()
        pass