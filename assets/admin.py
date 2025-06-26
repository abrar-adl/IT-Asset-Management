from django.contrib import admin
from .models import Asset

@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'ip_address', 'asset_type', 'manufacturer', 'model',
        'mac_address', 'serial_number', 'location',
        'status', 'network_range', 'discovered_date',
        'warranty_expiration', 'purchase_date', 'replacement_due',
    )
    search_fields = ('name', 'ip_address', 'serial_number')
    list_filter = ('status', 'asset_type', 'network_range')


@admin.display(description='Vulnerability Count')
def vulnerability_count(self, obj):
    return len(obj.get_vulnerability_list())
