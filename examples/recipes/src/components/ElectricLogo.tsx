import { SvgIcon, SvgIconProps } from "@mui/material";

interface ElectricLogoProps extends SvgIconProps {
  size?: number;
}

export const ElectricLogo = (props: ElectricLogoProps ) => (
  <SvgIcon {...props} style={{ fontSize: props.size }}>
    <svg xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 264 264"
        width="132"
        height="132">
      <path d="M136.992 53.1244C137.711 52.4029 138.683 52 139.692 52H200L114.008 138.089C113.289 138.811 112.317 139.213 111.308 139.213H51L136.992 53.1244Z" />
      <path d="M126.416 141.125C126.416 140.066 127.275 139.204 128.331 139.204H200L126.416 213V141.125Z"/>
    </svg>
  </SvgIcon>
)