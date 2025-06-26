import json
from django.db import models
from django.utils import timezone

class Asset(models.Model):
    ASSET_TYPES = [
        ('server', 'Server'),
        ('workstation', 'Workstation'),
        ('laptop', 'Laptop'),
        ('network', 'Network Device'),
        ('printer', 'Printer'),
    ]
    
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(unique=True, null=True, blank=True)
    asset_type = models.CharField(max_length=100, choices=ASSET_TYPES, default='workstation')
    manufacturer = models.CharField(max_length=100, blank=True, default='Unknown')
    discovered_date = models.DateTimeField(default=timezone.now)
    network_range = models.CharField(max_length=50, blank=True, null=True, default='unknown')
    mac_address = models.CharField(max_length=17, blank=True, null=True, default='')
    model = models.CharField(max_length=50, blank=True, null=True, default='')
    serial_number = models.CharField(max_length=50, blank=True, null=True, default='')
    location = models.CharField(max_length=100, blank=True, null=True, default='')

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('retired', 'Retired'),
        ('faulty', 'Faulty'),
    ]
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active'
    )

    warranty_expiration = models.DateField(null=True, blank=True)
    purchase_date = models.DateField(null=True, blank=True)
    replacement_due = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.asset_type})"

class ScanLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    network_range = models.CharField(max_length=50)
    found_devices = models.IntegerField()

    def __str__(self):
        return f"{self.network_range} — {self.found_devices} devices @ {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

class DetectedService(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    product = models.CharField(max_length=100)
    version = models.CharField(max_length=100)
    scanned_at = models.DateTimeField(auto_now_add=True)


class RiskScanResult(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    risk_score = models.IntegerField()
    risk_level = models.CharField(max_length=10)
    # Changed from JSONField to TextField for SQLite compatibility
    # This field will internally store the JSON string
    vulnerabilities_json = models.TextField(blank=True, default='[]')
    
    # This field will automatically update to the current time whenever the object is saved
    scanned_at = models.DateTimeField(auto_now=True) 

    @property
    def vulnerabilities(self):
        """
        Returns the vulnerabilities as a Python list. 
        This property handles deserialization from the JSON string.
        """
        try:
            # Ensure it's treated as a string before loading, and handle potential empty/null cases
            if self.vulnerabilities_json:
                loaded_data = json.loads(self.vulnerabilities_json)
                if isinstance(loaded_data, list):
                    return loaded_data
            return []
        except (json.JSONDecodeError, TypeError):
            # Fallback if there's an issue with the JSON string
            return []

    @vulnerabilities.setter
    def vulnerabilities(self, value):
        """
        Sets the vulnerabilities by converting a Python list to a JSON string.
        This property handles serialization to the JSON string.
        """
        if isinstance(value, list):
            self.vulnerabilities_json = json.dumps(value)
        else:
            # If a non-list value is attempted to be set, store an empty JSON list
            self.vulnerabilities_json = json.dumps([]) 

    def __str__(self):
        return f"Risk for {self.asset.name} - Level: {self.risk_level} (Last scan: {self.scanned_at.strftime('%Y-%m-%d %H:%M:%S')})"


# class ScanHistory(models.Model):
#     network = models.CharField(max_length=50)
#     asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
#     risk_score = models.IntegerField()
#     scanned_at = models.DateTimeField(auto_now_add=True)
