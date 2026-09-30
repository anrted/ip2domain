import asyncio
from .base import ProtocolPlugin
from ..protocols.dicom import association,parse_association,echo,echo_status,pdu
from ..transports.network import close_writer
from ..evidence import capture

class DICOMPlugin(ProtocolPlugin):
    name='dicom';protocols=('dicom',)
    async def enumerate(self,ctx):
        o=ctx.observation;await ctx.budget.protocol_tick(o.ip,'dicom')
        reader,writer=await ctx.budget.connect(o.ip,o.port)
        async def read():
            head=await reader.readexactly(6);length=int.from_bytes(head[2:6],'big')
            if length>16384:raise ValueError('DICOM size limit')
            return head+await reader.readexactly(length)
        try:
            writer.write(association(ctx.config.dicom_ae_title));await writer.drain()
            response=await asyncio.wait_for(read(),ctx.config.timeout);parsed=parse_association(response)
            if parsed is None:return
            evidence=capture(o,'dicom_association',response,source='Verification SOP only')
            if parsed.get('verification_accepted'):
                writer.write(echo());await writer.drain()
                response=await asyncio.wait_for(read(),ctx.config.timeout);status=echo_status(response)
                if status is not None:
                    # Only command-set status, never retain peer datasets.
                    capture(o,'dicom_c_echo',str(status),source='C-ECHO-RSP')
                    o.service('dicom',('medical',),c_echo_status=status,ae_title=ctx.config.dicom_ae_title,evidence=evidence,**parsed)
                writer.write(pdu(5,b'\x00'*4));await writer.drain()
        finally:await close_writer(writer)
